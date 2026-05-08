"""
BIP-39 mnemonic / seed tests.

The crucial property of this module is **byte-identity** with the TREZOR
reference vectors. Length and determinism alone are insufficient — they do
not catch a PBKDF2 iteration-collapse bug (see haskoin's W21 trap, where
a 1-iteration vs 2048-iteration regression flew under length-only tests).

Vectors taken from:
    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    (passphrase = "TREZOR" for all three)
"""

from __future__ import annotations

import pytest

from ouroboros.bip39 import (
    Bip39Error,
    WORDLIST,
    entropy_to_mnemonic,
    generate_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    validate_mnemonic,
)


# --- TREZOR vectors (passphrase = "TREZOR") ---

# Vector 1: 16-byte all-zero entropy -> 12 words.
V1_ENTROPY_HEX = "00000000000000000000000000000000"
V1_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)
V1_SEED_HEX = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)

# Vector 2: 16 bytes of 0x7f -> 12 words.
V2_ENTROPY_HEX = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
V2_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"
V2_SEED_HEX = (
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
    "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
)

# Vector 7 (24-word): 24 bytes of 0x80 -> 18 words; vector with 24 bytes
# from the TREZOR set is index 9. Use index 6 which is 24-byte/18-word.
# Actually we want a 24-word mnemonic. From the canonical vectors list,
# entry 9 ("ffff... × 32 bytes") is a 24-word vector.
V3_ENTROPY_HEX = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
V3_MNEMONIC = (
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
)
V3_SEED_HEX = (
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
    "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
)
V3_MASTER_XPRV = (
    "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
)


# --- byte-identity vector tests ---


@pytest.mark.parametrize(
    "entropy_hex, mnemonic, seed_hex",
    [
        (V1_ENTROPY_HEX, V1_MNEMONIC, V1_SEED_HEX),
        (V2_ENTROPY_HEX, V2_MNEMONIC, V2_SEED_HEX),
        (V3_ENTROPY_HEX, V3_MNEMONIC, V3_SEED_HEX),
    ],
    ids=["v1-12word-zero", "v2-12word-7f", "v3-24word-ff"],
)
def test_trezor_vector_entropy_to_mnemonic(entropy_hex, mnemonic, seed_hex):
    """Entropy -> mnemonic round-trip matches TREZOR exactly."""
    entropy = bytes.fromhex(entropy_hex)
    got = entropy_to_mnemonic(entropy)
    assert got == mnemonic.split(), (
        f"entropy_to_mnemonic mismatch: got {got!r}, want {mnemonic.split()!r}"
    )


@pytest.mark.parametrize(
    "entropy_hex, mnemonic, seed_hex",
    [
        (V1_ENTROPY_HEX, V1_MNEMONIC, V1_SEED_HEX),
        (V2_ENTROPY_HEX, V2_MNEMONIC, V2_SEED_HEX),
        (V3_ENTROPY_HEX, V3_MNEMONIC, V3_SEED_HEX),
    ],
    ids=["v1-12word-zero", "v2-12word-7f", "v3-24word-ff"],
)
def test_trezor_vector_mnemonic_to_entropy(entropy_hex, mnemonic, seed_hex):
    """Mnemonic -> entropy round-trip matches TREZOR exactly."""
    got = mnemonic_to_entropy(mnemonic)
    assert got.hex() == entropy_hex, (
        f"mnemonic_to_entropy mismatch: got {got.hex()}, want {entropy_hex}"
    )


@pytest.mark.parametrize(
    "entropy_hex, mnemonic, seed_hex",
    [
        (V1_ENTROPY_HEX, V1_MNEMONIC, V1_SEED_HEX),
        (V2_ENTROPY_HEX, V2_MNEMONIC, V2_SEED_HEX),
        (V3_ENTROPY_HEX, V3_MNEMONIC, V3_SEED_HEX),
    ],
    ids=["v1-12word-zero", "v2-12word-7f", "v3-24word-ff"],
)
def test_trezor_vector_mnemonic_to_seed_byte_identity(entropy_hex, mnemonic, seed_hex):
    """**REQUIRED** byte-identity check on PBKDF2-HMAC-SHA512.

    This is the single test that catches the haskoin W21
    iteration-collapse bug. Length + determinism are insufficient.
    """
    seed = mnemonic_to_seed(mnemonic, "TREZOR")
    assert seed.hex() == seed_hex, (
        f"PBKDF2 byte-identity FAILED for {mnemonic!r}\n"
        f"  got:  {seed.hex()}\n"
        f"  want: {seed_hex}"
    )
    assert len(seed) == 64


# --- structural tests ---


def test_wordlist_size():
    assert len(WORDLIST) == 2048
    assert WORDLIST[0] == "abandon"
    assert WORDLIST[2047] == "zoo"


@pytest.mark.parametrize("ent_bytes,word_count", [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)])
def test_entropy_lengths_produce_expected_word_counts(ent_bytes, word_count):
    entropy = bytes(ent_bytes)
    words = entropy_to_mnemonic(entropy)
    assert len(words) == word_count
    # Round-trip back to entropy.
    assert mnemonic_to_entropy(words) == entropy


def test_invalid_entropy_length_rejected():
    with pytest.raises(Bip39Error):
        entropy_to_mnemonic(b"\x00" * 15)
    with pytest.raises(Bip39Error):
        entropy_to_mnemonic(b"\x00" * 17)
    with pytest.raises(Bip39Error):
        entropy_to_mnemonic(b"\x00" * 33)


def test_invalid_word_count_rejected():
    with pytest.raises(Bip39Error):
        mnemonic_to_entropy(["abandon"] * 11)
    with pytest.raises(Bip39Error):
        mnemonic_to_entropy(["abandon"] * 13)
    with pytest.raises(Bip39Error):
        mnemonic_to_entropy(["abandon"] * 25)


def test_unknown_word_rejected():
    bogus = V1_MNEMONIC.split()
    bogus[0] = "notarealword"
    with pytest.raises(Bip39Error, match="not in BIP-39 English wordlist"):
        mnemonic_to_entropy(bogus)


def test_corrupt_checksum_rejected():
    """Swap a checksum-invalid word in V1 and assert validation fails.

    V1's last word is 'about' (one of the few checksum-distinct words for
    all-zero entropy). Replacing it with 'abandon' gives a structurally
    valid mnemonic with a wrong checksum.
    """
    corrupted = V1_MNEMONIC.split()
    corrupted[-1] = "abandon"
    with pytest.raises(Bip39Error, match="invalid mnemonic checksum"):
        mnemonic_to_entropy(corrupted)
    with pytest.raises(Bip39Error, match="invalid mnemonic checksum"):
        validate_mnemonic(corrupted)


def test_validate_mnemonic_accepts_string_or_list():
    # String form
    validate_mnemonic(V1_MNEMONIC)
    # List form
    validate_mnemonic(V1_MNEMONIC.split())


def test_mnemonic_to_seed_accepts_string_or_list():
    seed_a = mnemonic_to_seed(V1_MNEMONIC, "TREZOR")
    seed_b = mnemonic_to_seed(V1_MNEMONIC.split(), "TREZOR")
    assert seed_a == seed_b
    assert seed_a.hex() == V1_SEED_HEX


def test_passphrase_changes_seed():
    seed_no_pw = mnemonic_to_seed(V1_MNEMONIC, "")
    seed_trezor = mnemonic_to_seed(V1_MNEMONIC, "TREZOR")
    assert seed_no_pw != seed_trezor
    # Empty-passphrase seed should also be 64 bytes and deterministic.
    assert len(seed_no_pw) == 64
    assert mnemonic_to_seed(V1_MNEMONIC, "") == seed_no_pw


def test_passphrase_nfkd_normalised():
    """A passphrase with composed/decomposed forms must yield the same seed.

    "café" can be encoded either as U+00E9 (composed) or U+0065 U+0301
    (decomposed). NFKD normalisation forces the latter, so both must
    produce identical seeds.
    """
    composed = "café"  # café (precomposed)
    decomposed = "café"  # cafe + combining acute
    assert composed != decomposed
    assert mnemonic_to_seed(V1_MNEMONIC, composed) == mnemonic_to_seed(
        V1_MNEMONIC, decomposed
    )


@pytest.mark.parametrize("bits", [128, 160, 192, 224, 256])
def test_generate_mnemonic_lengths(bits):
    words = generate_mnemonic(bits)
    expected = {128: 12, 160: 15, 192: 18, 224: 21, 256: 24}[bits]
    assert len(words) == expected
    # Generated mnemonic must validate cleanly.
    validate_mnemonic(words)


def test_generate_mnemonic_rejects_invalid_bits():
    with pytest.raises(Bip39Error):
        generate_mnemonic(64)
    with pytest.raises(Bip39Error):
        generate_mnemonic(129)


def test_generate_mnemonic_default_is_12_words():
    words = generate_mnemonic()
    assert len(words) == 12


# --- BIP-32 integration test (mnemonic -> seed -> HD master) ---


def test_bip39_to_bip32_master_xprv_v1():
    """Full BIP-39 + BIP-32 round-trip.

    Vector 1 (all-zero entropy + "TREZOR" passphrase) yields a known
    master xprv. The xprv is part of the canonical TREZOR vector set
    and is generated by feeding the BIP-39 seed into BIP-32
    ``HDKey.from_seed``.
    """
    from ouroboros.wallet import HDKey

    seed = mnemonic_to_seed(V1_MNEMONIC, "TREZOR")
    master = HDKey.from_seed(seed, network="mainnet")
    expected_xprv = (
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    )
    assert master.serialize_xprv() == expected_xprv
