"""
MuHash3072 -- multiplicative incremental set hash, 3072-bit modulus.

This module is a Python port of Bitcoin Core's
``src/crypto/muhash.{h,cpp}``. MuHash maps each set element through a
PRF (SHA-256 then 6 ChaCha20 keystream blocks) into the multiplicative
group of integers modulo the 3072-bit safe prime ``p = 2**3072 - 1103717``.
Insert multiplies the running numerator, Remove multiplies the running
denominator, and Finalize collapses ``num / denom mod p`` to a 32-byte
SHA-256 over the little-endian 384-byte representative.

References:
  - bitcoin-core/src/crypto/muhash.{h,cpp}                    -- C++ Num3072 / MuHash3072
  - bitcoin-core/test/functional/test_framework/crypto/muhash.py
                                                              -- pure-Python reference
  - bitcoin-core/src/kernel/coinstats.cpp (TxOutSer)          -- Core element format
  - https://cseweb.ucsd.edu/~mihir/papers/inchash.pdf         -- MuHash construction

Python's unbounded-precision int makes this a ~50-line implementation:
no signed-limb safegcd, no manual ChaCha20 -- both are delegated.

Performance note: Insert/Remove costs ~6 ChaCha20 blocks plus one
3072-bit modular multiplication. Sufficient for snapshot validation,
not optimized for live UTXO accounting in the hot path.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# 2^3072 - 1103717 is the largest 3072-bit safe prime (Core
# crypto/muhash.cpp:32 MAX_PRIME_DIFF).
MODULUS: int = (1 << 3072) - 1103717

# 384 bytes = 3072 bits (Core Num3072::BYTE_SIZE).
NUM3072_BYTES: int = 384

# Number of 64-byte ChaCha20 blocks needed to fill 384 bytes.
_CHACHA_BLOCKS: int = NUM3072_BYTES // 64  # 6

# 12-byte nonce, all-zero (Core uses ChaCha20Aligned with no nonce input).
_ZERO_NONCE_12: bytes = b"\x00" * 12


def _chacha20_block(key32: bytes, counter: int) -> bytes:
    """64-byte ChaCha20 keystream block with a zero 12-byte nonce.

    Equivalent to Core's
        ChaCha20Aligned{key32}.Keystream(out_64)
    invoked once per counter, where the cryptography library's IV input
    is the 16-byte concatenation of the 32-bit LE counter and the
    12-byte nonce.

    We delegate to ``cryptography.hazmat`` (already a hard dependency
    via BIP-324 transport) rather than ship a hand-rolled ChaCha20.
    """
    iv16 = counter.to_bytes(4, "little") + _ZERO_NONCE_12
    enc = Cipher(algorithms.ChaCha20(key32, iv16), mode=None).encryptor()
    # XOR a 64-byte zero buffer to extract the raw keystream.
    return enc.update(b"\x00" * 64)


def data_to_num3072(data32: bytes) -> int:
    """Map a 32-byte SHA-256 digest to a 3072-bit integer (mod-free).

    Generates 6 ChaCha20 blocks (counters 0..5), keyed by ``data32``,
    nonce all-zero, and interprets the concatenation as a 384-byte
    little-endian unsigned integer. Mirrors:

      - bitcoin-core/test/functional/test_framework/crypto/muhash.py
        ``data_to_num3072``
      - bitcoin-core/src/crypto/muhash.cpp ``MuHash3072::ToNum3072``
    """
    if len(data32) != 32:
        raise ValueError("data_to_num3072 expects a 32-byte SHA-256 digest")
    blocks = b"".join(_chacha20_block(data32, c) for c in range(_CHACHA_BLOCKS))
    return int.from_bytes(blocks, "little")


def _element_to_num(element: bytes) -> int:
    """SHA-256 the variable-length input, then expand via ChaCha20."""
    digest = hashlib.sha256(element).digest()
    return data_to_num3072(digest)


class MuHash3072:
    """Incremental multiset hash mod (2**3072 - 1103717).

    The accumulator stores a numerator and denominator independently so
    that Insert and Remove are pure modular multiplications -- no
    expensive modular inverse on the hot path. Finalize folds the two
    sides together via a single ``pow(denom, -1, p)`` and emits a
    32-byte SHA-256 over the 384-byte LE representative.

    Operations are commutative and associative, so the order of
    insertions/removals does not affect the final digest. This is what
    makes MuHash suitable for UTXO-set commitments: the digest depends
    on the set content, not on iteration order.
    """

    __slots__ = ("numerator", "denominator")

    def __init__(self, element: bytes | None = None) -> None:
        """Empty multiset, or a singleton if ``element`` is given.

        The Core constructor signature ``MuHash3072(span)`` initializes
        the numerator from a single element; we mirror that.
        """
        self.numerator: int = 1
        self.denominator: int = 1
        if element is not None:
            self.numerator = _element_to_num(element) % MODULUS

    def insert(self, element: bytes) -> "MuHash3072":
        """Multiply the numerator by H(element). Returns self."""
        self.numerator = (self.numerator * _element_to_num(element)) % MODULUS
        return self

    def remove(self, element: bytes) -> "MuHash3072":
        """Multiply the denominator by H(element). Returns self."""
        self.denominator = (self.denominator * _element_to_num(element)) % MODULUS
        return self

    def __imul__(self, other: "MuHash3072") -> "MuHash3072":
        """Combine two MuHash sets (set union semantics)."""
        if not isinstance(other, MuHash3072):
            return NotImplemented
        self.numerator = (self.numerator * other.numerator) % MODULUS
        self.denominator = (self.denominator * other.denominator) % MODULUS
        return self

    def __itruediv__(self, other: "MuHash3072") -> "MuHash3072":
        """Set difference -- swaps numerator/denominator on ``other``."""
        if not isinstance(other, MuHash3072):
            return NotImplemented
        self.numerator = (self.numerator * other.denominator) % MODULUS
        self.denominator = (self.denominator * other.numerator) % MODULUS
        return self

    def digest(self) -> bytes:
        """32-byte SHA-256 over the 384-byte LE representative.

        Format matches Core's ``MuHash3072::Finalize``:
          1. Compute ``val = num / denom mod p``  (one modular inverse).
          2. Encode ``val`` as 384 bytes little-endian.
          3. Return SHA-256(encoded).

        Display order (the "natural reading" hex you see in
        AssumeutxoData) is the byte-reverse of this digest, since Core
        prints uint256 big-endian.
        """
        val = (self.numerator * pow(self.denominator, -1, MODULUS)) % MODULUS
        return hashlib.sha256(val.to_bytes(NUM3072_BYTES, "little")).digest()

    # ------------------------------------------------------------------
    # Wire-format helpers for serializing the running accumulator. Core
    # uses two 384-byte LE Num3072 limbs (no length prefix); we expose
    # the same 768-byte blob.
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """768-byte serialization: num || denom, each 384 bytes LE.

        Matches Core's ``SERIALIZE_METHODS(MuHash3072, obj)`` which
        serializes the numerator's 48 LE64 limbs followed by the
        denominator's. Both fields are kept un-reduced: a freshly-
        deserialized MuHash3072 with values larger than the modulus
        produces the same Finalize output as the reduced form (Core
        crypto_tests muhash overflow vector exercises this).
        """
        return (
            self.numerator.to_bytes(NUM3072_BYTES, "little")
            + self.denominator.to_bytes(NUM3072_BYTES, "little")
        )

    @classmethod
    def deserialize(cls, blob: bytes) -> "MuHash3072":
        """Inverse of :meth:`serialize`; accepts un-reduced limbs."""
        if len(blob) != 2 * NUM3072_BYTES:
            raise ValueError(
                f"MuHash3072.deserialize expects {2 * NUM3072_BYTES} bytes,"
                f" got {len(blob)}"
            )
        out = cls()
        out.numerator = int.from_bytes(blob[:NUM3072_BYTES], "little")
        out.denominator = int.from_bytes(blob[NUM3072_BYTES:], "little")
        return out


# ---------------------------------------------------------------------------
# Coin element encoding (TxOutSer in Core, kernel/coinstats.cpp:46-51)
# ---------------------------------------------------------------------------


def _write_compact_size(n: int) -> bytes:
    """Bitcoin CompactSize encoding (varint of unsigned ints)."""
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def coin_element(
    txid: bytes,
    vout: int,
    height: int,
    is_coinbase: bool,
    amount: int,
    script_pubkey: bytes,
) -> bytes:
    """Serialize a UTXO entry the way Core's ``TxOutSer`` does.

    Layout (kernel/coinstats.cpp:46-51):

        outpoint            -- 32-byte txid (internal order) + uint32 LE vout
        code                -- uint32 LE: (height << 1) | fCoinBase
        value               -- int64 LE
        scriptPubKey        -- CompactSize length + raw bytes

    The output of this helper is the byte-string fed to MuHash3072
    Insert/Remove for UTXO-set commitments.
    """
    if len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    code = (int(height) << 1) | (1 if is_coinbase else 0)
    return (
        bytes(txid)
        + struct.pack("<I", int(vout))
        + struct.pack("<I", code)
        + struct.pack("<q", int(amount))
        + _write_compact_size(len(script_pubkey))
        + bytes(script_pubkey)
    )


__all__ = [
    "MODULUS",
    "NUM3072_BYTES",
    "MuHash3072",
    "coin_element",
    "data_to_num3072",
]
