"""
BIP 324 — v2 P2P Transport Protocol.

Implements encrypted and authenticated P2P connections using:
- ElligatorSwift key exchange (X-only ECDH over secp256k1)
- ChaCha20-Poly1305 AEAD for packet contents (with periodic rekey)
- Plain ChaCha20 for the 3-byte length prefix (with periodic rekey)
- Per-direction garbage terminators sent right after the ellswift pubkey

Reference: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
           bitcoin-core/src/bip324.{cpp,h}
           bitcoin-core/src/test/bip324_tests.cpp
           bitcoin-core/test/functional/test_framework/v2_p2p.py
           bitcoin-core/test/functional/test_framework/crypto/{chacha20.py,bip324_cipher.py}
           libsecp256k1 ellswift module (modules/ellswift/main_impl.h)

ECDH backend: real ``secp256k1_ellswift_create`` /
``secp256k1_ellswift_xdh`` with the BIP 324 hash function, called
through ``coincurve``'s bundled libsecp256k1 cffi bindings.

Packet-format compliance (this commit): the key derivation now follows
BIP 324 exactly — HKDF-Extract over salt ``b'bitcoin_v2_shared_secret'
+ network_magic`` and HKDF-Expand for ``initiator_L``, ``initiator_P``,
``responder_L``, ``responder_P``, ``garbage_terminators``,
``session_id``.  Length cipher is FSChaCha20, contents cipher is
FSChaCha20Poly1305 with a 1-byte header carrying the IGNORE bit.  Both
ciphers rekey every ``REKEY_INTERVAL`` packets via the BIP 324 schedule.

Validated against Bitcoin Core's published packet test vectors
(``bitcoin-core/src/test/bip324_tests.cpp::packet_test_vectors``); see
``tests/test_bip324_packet_vectors.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- Real secp256k1 ElligatorSwift / XDH (BIP 324) ---
#
# coincurve ships its own libsecp256k1 with the ellswift module enabled.
# We bind directly through its cffi handle rather than re-vendoring or
# rolling a custom ctypes wrapper — both because coincurve is already a
# hard dependency of ouroboros (used elsewhere for secp256k1 ops) and
# because its build pins a known-good libsecp256k1 version with the
# ellswift symbols.  See camlcoin/lib/schnorr_stubs.c:622-732 (commit
# 559c3d1) for the C-wrapper analog of this binding.
from coincurve._libsecp256k1 import ffi as _secp_ffi, lib as _secp_lib
from coincurve.context import GLOBAL_CONTEXT as _SECP_CTX

if not all(
    hasattr(_secp_lib, sym)
    for sym in (
        "secp256k1_ellswift_create",
        "secp256k1_ellswift_xdh",
        "secp256k1_ellswift_xdh_hash_function_bip324",
    )
):  # pragma: no cover — guarded by hard dep on coincurve >= 21.x
    raise ImportError(
        "coincurve's libsecp256k1 is missing ellswift symbols required "
        "for BIP 324 v2 transport; please upgrade coincurve to >= 21.x"
    )


def secp256k1_ellswift_create(
    secret_key: bytes, aux_rand32: bytes
) -> bytes:
    """Wrap ``secp256k1_ellswift_create``.

    Returns the 64-byte ElligatorSwift-encoded public key for ``secret_key``,
    using ``aux_rand32`` to randomise the encoding (see BIP 324 §
    "ElligatorSwift encoding of curve X coordinates").

    Both inputs MUST be exactly 32 bytes.  ``secret_key`` MUST be a valid
    secp256k1 scalar (1 <= d < n).
    """
    if len(secret_key) != 32:
        raise ValueError("secret_key must be 32 bytes")
    if len(aux_rand32) != 32:
        raise ValueError("aux_rand32 must be 32 bytes")
    out64 = _secp_ffi.new("unsigned char[64]")
    sk_buf = _secp_ffi.new("unsigned char[32]", secret_key)
    aux_buf = _secp_ffi.new("unsigned char[32]", aux_rand32)
    ok = _secp_lib.secp256k1_ellswift_create(
        _SECP_CTX.ctx, out64, sk_buf, aux_buf
    )
    if not ok:  # pragma: no cover — only reachable on invalid secret
        raise ValueError("secp256k1_ellswift_create failed (invalid secret?)")
    return bytes(out64)


def secp256k1_ellswift_xdh(
    ell_ours: bytes,
    ell_theirs: bytes,
    secret_key: bytes,
    initiating: bool,
) -> bytes:
    """Wrap ``secp256k1_ellswift_xdh`` with the BIP 324 hash function.

    Returns the 32-byte BIP 324 ECDH shared secret.  Matches
    libsecp256k1's reference convention from
    ``modules/ellswift/tests_impl.h:217``::

        party = !initiating
        ell_a64 = party ? theirs : ours
        ell_b64 = party ? ours   : theirs

    so initiator and responder feed the same ordered (ell_a, ell_b)
    pair and produce the same shared secret — that's the whole point
    of an XDH.
    """
    if len(ell_ours) != 64 or len(ell_theirs) != 64:
        raise ValueError("ellswift pubkeys must be 64 bytes")
    if len(secret_key) != 32:
        raise ValueError("secret_key must be 32 bytes")
    party = 0 if initiating else 1
    ell_a64 = ell_theirs if party else ell_ours
    ell_b64 = ell_ours if party else ell_theirs
    out32 = _secp_ffi.new("unsigned char[32]")
    a_buf = _secp_ffi.new("unsigned char[64]", ell_a64)
    b_buf = _secp_ffi.new("unsigned char[64]", ell_b64)
    sk_buf = _secp_ffi.new("unsigned char[32]", secret_key)
    hash_fn = _secp_lib.secp256k1_ellswift_xdh_hash_function_bip324
    ok = _secp_lib.secp256k1_ellswift_xdh(
        _SECP_CTX.ctx,
        out32,
        a_buf,
        b_buf,
        sk_buf,
        party,
        hash_fn,
        _secp_ffi.NULL,
    )
    if not ok:  # pragma: no cover — invalid pubkey would already be rejected
        raise ValueError("secp256k1_ellswift_xdh failed")
    return bytes(out32)


def _generate_secret_key() -> bytes:
    """Generate a uniformly random 32-byte secp256k1 scalar (1 <= d < n)."""
    # secp256k1's curve order n is just below 2^256, so the rejection
    # rate of os.urandom(32) is negligible (~2^-128).  But ellswift_create
    # itself rejects 0 and values >= n, so we loop defensively.
    while True:
        sk = os.urandom(32)
        if sk != b"\x00" * 32:
            return sk


# --- constants -------------------------------------------------------------

NETWORK_MAGIC_V2 = b""    # v2 has no network magic; first 64 bytes are ESwift keys
REKEY_INTERVAL = 224      # re-key after this many messages (BIP 324)

# BIP 324 transport versioning
TRANSPORT_V1 = 1
TRANSPORT_V2 = 2

# Fixed BIP 324 layout constants.  Mirrors bitcoin-core/src/bip324.h.
LENGTH_FIELD_LEN = 3
HEADER_LEN = 1
GARBAGE_TERMINATOR_LEN = 16
SESSION_ID_LEN = 32
MAX_GARBAGE_LEN = 4095
CHACHA20POLY1305_EXPANSION = 16  # Poly1305 tag


class PacketType(IntEnum):
    """BIP 324 packet header flag bit values.

    Per BIP 324, the high bit of the 1-byte header (``IGNORE_BIT_POS = 7``)
    flags a decoy / "ignore" packet.  All other bits MUST be zero.
    """
    GENUINE = 0x00
    DECOY = 0x80


IGNORE_BIT = 0x80  # high bit of the BIP 324 header byte


# --- BIP 324 short message-ID table ---------------------------------------
#
# Per BIP 324, the *contents* of an application packet are wrapped as:
#
#     short_id (1 byte, 0x01..0x1c) + payload                  (short form)
#  OR
#     0x00 + 12-byte ASCII command (NUL-padded) + payload      (long form)
#
# The 24-byte v1 magic|cmd|len|checksum header is NOT part of v2 contents —
# it is replaced by this 1- or 13-byte type prefix.  Reference:
# bitcoin-core/src/net.cpp ``V2_MESSAGE_IDS`` (constexpr array of 33) and
# ``V2Transport::SetMessageToSend`` / ``GetMessageType``.
#
# Index 0 ("") is reserved for long-form encoding; indices 29-32 are the
# four "Unimplemented" slots BIP 324 reserves for future use.  We do not
# emit them on the wire.  On decode, unknown short IDs fall through to
# ``None`` and the caller drops the packet (Core net.cpp:1426-1428).
V2_MESSAGE_IDS: tuple[str, ...] = (
    "",            # 0  — long encoding marker
    "addr",        # 1
    "block",       # 2
    "blocktxn",    # 3
    "cmpctblock",  # 4
    "feefilter",   # 5
    "filteradd",   # 6
    "filterclear", # 7
    "filterload",  # 8
    "getblocks",   # 9
    "getblocktxn", # 10
    "getdata",     # 11
    "getheaders",  # 12
    "headers",     # 13
    "inv",         # 14
    "mempool",     # 15
    "merkleblock", # 16
    "notfound",    # 17
    "ping",        # 18
    "pong",        # 19
    "sendcmpct",   # 20
    "tx",          # 21
    "getcfilters", # 22
    "cfilter",     # 23
    "getcfheaders",# 24
    "cfheaders",   # 25
    "getcfcheckpt",# 26
    "cfcheckpt",   # 27
    "addrv2",      # 28
    # 29-32 reserved for future use per BIP 324; do not emit.
)

_V2_SHORT_ID_BY_COMMAND: dict[str, int] = {
    cmd: idx for idx, cmd in enumerate(V2_MESSAGE_IDS) if cmd
}


def v2_short_id(command: str) -> int | None:
    """Return the 1-byte BIP 324 short ID for ``command`` or ``None``.

    ``None`` means the message MUST be encoded with the long (12-byte)
    form.  This is the encoder side; only the BIP 324 spec range 1..28
    is emitted.
    """
    return _V2_SHORT_ID_BY_COMMAND.get(command)


def v2_command_from_short_id(short_id: int) -> str | None:
    """Return the command name for a BIP 324 short ID, or ``None``.

    Decoder side.  Only the BIP 324 spec range 1..28 is recognised here;
    unknown / extended / reserved IDs (0, 29..255) return ``None`` and
    the caller should drop the packet without disconnecting the peer
    (forward-compat with future BIP 324 amendments).
    """
    if 1 <= short_id < len(V2_MESSAGE_IDS):
        cmd = V2_MESSAGE_IDS[short_id]
        return cmd if cmd else None
    return None


def encode_v2_contents(command: str, payload: bytes) -> bytes:
    """Wrap a (command, payload) into BIP 324 v2 packet contents.

    Mirrors ``V2Transport::SetMessageToSend`` (bitcoin-core/src/net.cpp:
    1484-1514).  The 24-byte v1 magic|cmd|len|checksum header is NOT
    included — it is the v1 framing that v2 replaces.
    """
    short_id = v2_short_id(command)
    if short_id is not None:
        return bytes([short_id]) + payload
    # Long form: 0x00 + 12-byte NUL-padded ASCII command + payload.
    cmd_bytes = command.encode("ascii")
    if len(cmd_bytes) > 12:
        raise ValueError(f"v2 long-form command too long: {command!r}")
    cmd_field = cmd_bytes + b"\x00" * (12 - len(cmd_bytes))
    return b"\x00" + cmd_field + payload


def decode_v2_contents(contents: bytes) -> tuple[str, bytes] | None:
    """Inverse of :func:`encode_v2_contents`.

    Returns ``(command, payload)`` or ``None`` if the contents are
    malformed / use an unknown short ID.  Mirrors
    ``V2Transport::GetMessageType`` (bitcoin-core/src/net.cpp:1415-1453).
    """
    if not contents:
        return None
    first = contents[0]
    rest = contents[1:]
    if first != 0:
        cmd = v2_command_from_short_id(first)
        if cmd is None:
            return None
        return cmd, rest
    # Long encoding: must have at least 12 bytes for the command field.
    if len(rest) < 12:
        return None
    cmd_field = rest[:12]
    payload = rest[12:]
    # The first 0x00 terminates; bytes after must also be 0x00, and bytes
    # before must be printable ASCII (Core net.cpp:1437-1448).
    msg_type_len = 0
    while msg_type_len < 12 and cmd_field[msg_type_len] != 0:
        b = cmd_field[msg_type_len]
        if b < 0x20 or b > 0x7F:
            return None
        msg_type_len += 1
    while msg_type_len < 12:
        if cmd_field[msg_type_len] != 0:
            return None
        msg_type_len += 1
    try:
        command = cmd_field.rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError:
        return None
    return command, payload


# --- network magic mapping for HKDF salt ----------------------------------
#
# BIP 324's salt = ``b'bitcoin_v2_shared_secret' + network_magic`` where
# ``network_magic`` is the 4-byte ``pchMessageStart`` constant (the same
# bytes that prefix v1 message frames).  Bitcoin Core stores them as raw
# byte arrays (e.g. ``f9 be b4 d9`` for mainnet); ouroboros stores them
# as little-endian uint32s in p2p_messages.MAGIC_*.  We expose the byte
# form here to avoid a circular import.

_MAGIC_BYTES_BY_NETWORK: dict[str, bytes] = {
    "mainnet":  bytes([0xf9, 0xbe, 0xb4, 0xd9]),
    "main":     bytes([0xf9, 0xbe, 0xb4, 0xd9]),
    "testnet":  bytes([0x0b, 0x11, 0x09, 0x07]),
    "testnet3": bytes([0x0b, 0x11, 0x09, 0x07]),
    "testnet4": bytes([0x1c, 0x16, 0x3f, 0x28]),
    "regtest":  bytes([0xfa, 0xbf, 0xb5, 0xda]),
    "signet":   bytes([0x0a, 0x03, 0xcf, 0x40]),
}


def _network_magic_bytes(network: str) -> bytes:
    """Return the 4-byte network magic used as the HKDF salt suffix.

    Defaults to mainnet on unknown network strings; this matches the
    bitcoin-core packet test vectors which use mainnet exclusively
    (see bip324_tests.cpp::packet_test_vectors and SelectParams(MAIN)).
    """
    return _MAGIC_BYTES_BY_NETWORK.get(network.lower(), bytes([0xf9, 0xbe, 0xb4, 0xd9]))


# --- HKDF-SHA256 (RFC 5869, multi-block expand) ---------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF-Expand length too large")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf_sha256(*, salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract-then-expand).  Public for vector tests."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# tagged hash (BIP 340-style) — used by legacy CipherState rekey path
def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# --- ChaCha20 block primitive (RFC 8439 IETF variant) ---------------------

def _chacha20_block(key: bytes, nonce_12: bytes, counter: int) -> bytes:
    """64-byte ChaCha20 keystream block (IETF variant, 32-bit counter).

    Equivalent to bitcoin-core/test/functional/test_framework/crypto/
    chacha20.py::chacha20_block.  We implement on top of
    ``cryptography.hazmat`` because it is already a hard dependency
    (used for ChaCha20Poly1305) and the bundled implementation is
    constant-time C; the test-framework Python version is documented as
    "trivially vulnerable to side channel attacks. Do not use for
    anything but tests."
    """
    iv16 = counter.to_bytes(4, "little") + nonce_12
    enc = Cipher(algorithms.ChaCha20(key, iv16), None).encryptor()
    return enc.update(b"\x00" * 64)


# --- FSChaCha20 (length cipher) -------------------------------------------

class FSChaCha20:
    """Re-keying ChaCha20 stream cipher used for BIP 324 length encryption.

    Matches bitcoin-core's reference implementation in
    ``test/functional/test_framework/crypto/chacha20.py`` exactly:

    - Each chunk is XOR'd with fresh keystream bytes drawn from a
      ChaCha20 instance keyed by ``self._key``.
    - The 12-byte nonce is ``\\x00\\x00\\x00\\x00`` || little-endian-8
      (chunk_counter // rekey_interval).
    - The block counter starts at 0 and increments per 64-byte
      keystream block produced; it resets when the key rotates.
    - After every ``rekey_interval`` chunks (BIP 324 default = 224)
      the next 32 bytes of keystream become the new key, and the
      block + nonce counters reset.
    """

    def __init__(self, initial_key: bytes, rekey_interval: int = REKEY_INTERVAL):
        if len(initial_key) != 32:
            raise ValueError("FSChaCha20 key must be 32 bytes")
        self._key = initial_key
        self._rekey_interval = rekey_interval
        self._block_counter = 0
        self._chunk_counter = 0
        self._keystream = b""

    def _get_keystream_bytes(self, nbytes: int) -> bytes:
        while len(self._keystream) < nbytes:
            nonce = (
                (0).to_bytes(4, "little")
                + (self._chunk_counter // self._rekey_interval).to_bytes(8, "little")
            )
            self._keystream += _chacha20_block(self._key, nonce, self._block_counter)
            self._block_counter += 1
        ret = self._keystream[:nbytes]
        self._keystream = self._keystream[nbytes:]
        return ret

    def crypt(self, chunk: bytes) -> bytes:
        ks = self._get_keystream_bytes(len(chunk))
        ret = bytes(ks[i] ^ chunk[i] for i in range(len(chunk)))
        if ((self._chunk_counter + 1) % self._rekey_interval) == 0:
            # Rotate key from the next 32 bytes of the current keystream
            # before resetting block counter and clearing the buffer.
            self._key = self._get_keystream_bytes(32)
            self._block_counter = 0
            self._keystream = b""
        self._chunk_counter += 1
        return ret


# --- ChaCha20-Poly1305 AEAD (RFC 8439) ------------------------------------

def _aead_chacha20_poly1305_encrypt(
    key: bytes, nonce_12: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    """RFC 8439 AEAD_CHACHA20_POLY1305 encrypt.  Thin wrapper over
    ``cryptography``'s constant-time C implementation, exposed because
    BIP 324 needs the IETF nonce shape ``(packet_counter % rekey_interval,
    packet_counter // rekey_interval)`` rather than a free-form 12-byte
    nonce.
    """
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce_12, plaintext, aad)


def _aead_chacha20_poly1305_decrypt(
    key: bytes, nonce_12: bytes, aad: bytes, ciphertext: bytes
) -> bytes | None:
    """RFC 8439 AEAD_CHACHA20_POLY1305 decrypt.  Returns ``None`` on
    authentication failure rather than raising, matching the
    test-framework reference implementation.
    """
    try:
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce_12, ciphertext, aad)
    except Exception:
        return None


# --- FSChaCha20Poly1305 (contents cipher) ---------------------------------

class FSChaCha20Poly1305:
    """Re-keying ChaCha20-Poly1305 AEAD used for BIP 324 packet contents.

    Matches bitcoin-core reference (``bip324_cipher.py::FSChaCha20Poly1305``):

    - Per-packet nonce =
      ``LE32(packet_counter % rekey_interval) || LE64(packet_counter // rekey_interval)``
    - Every ``rekey_interval`` packets the key is rotated to the first 32
      bytes of ``aead_chacha20_poly1305_encrypt(old_key, FFFFFFFF||LE64(epoch), b'', \\0*32)``.
    - The packet counter is monotone and never resets.
    """

    def __init__(self, initial_key: bytes, rekey_interval: int = REKEY_INTERVAL):
        if len(initial_key) != 32:
            raise ValueError("FSChaCha20Poly1305 key must be 32 bytes")
        self._key = initial_key
        self._rekey_interval = rekey_interval
        self._packet_counter = 0

    def _nonce(self) -> bytes:
        return (
            (self._packet_counter % self._rekey_interval).to_bytes(4, "little")
            + (self._packet_counter // self._rekey_interval).to_bytes(8, "little")
        )

    def _maybe_rekey(self, current_nonce: bytes) -> None:
        if (self._packet_counter + 1) % self._rekey_interval == 0:
            rekey_nonce = b"\xFF\xFF\xFF\xFF" + current_nonce[4:]
            new_key = _aead_chacha20_poly1305_encrypt(
                self._key, rekey_nonce, b"", b"\x00" * 32
            )[:32]
            self._key = new_key

    def encrypt(self, aad: bytes, plaintext: bytes) -> bytes:
        nonce = self._nonce()
        ct = _aead_chacha20_poly1305_encrypt(self._key, nonce, aad, plaintext)
        self._maybe_rekey(nonce)
        self._packet_counter += 1
        return ct

    def decrypt(self, aad: bytes, ciphertext: bytes) -> bytes | None:
        nonce = self._nonce()
        pt = _aead_chacha20_poly1305_decrypt(self._key, nonce, aad, ciphertext)
        # Even on auth failure we MUST advance the schedule, otherwise
        # the receiver desyncs on the very next packet.  bitcoin-core
        # does the same thing — the connection is supposed to drop on
        # auth failure anyway, so the post-failure state is moot.
        self._maybe_rekey(nonce)
        self._packet_counter += 1
        return pt


# --- legacy CipherState (kept for compat with the rekey unit test) -------

@dataclass
class CipherState:
    """One-key-per-direction ChaCha20-Poly1305 wrapper.

    Pre-BIP-324 ouroboros used a single nonce-counter cipher per
    direction.  The proper BIP 324 transport now lives in
    ``BIP324Cipher`` / ``V2Transport`` with separate length and contents
    keys; this class is retained as a thin shim only so the legacy
    ``test_rekey_happens`` regression test continues to pass.

    New code should NOT use ``CipherState``.  It is an internal compat
    surface scheduled for removal once the wiring tests no longer
    reference ``send_cipher.key`` / ``recv_cipher.key`` directly.
    """
    key: bytes
    nonce_counter: int = 0

    def _nonce(self) -> bytes:
        return struct.pack("<IQ", 0, self.nonce_counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        cipher = ChaCha20Poly1305(self.key)
        ct = cipher.encrypt(self._nonce(), plaintext, aad)
        self.nonce_counter += 1
        if self.nonce_counter % REKEY_INTERVAL == 0:
            self._rekey()
        return ct

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        cipher = ChaCha20Poly1305(self.key)
        pt = cipher.decrypt(self._nonce(), ciphertext, aad)
        self.nonce_counter += 1
        if self.nonce_counter % REKEY_INTERVAL == 0:
            self._rekey()
        return pt

    def _rekey(self) -> None:
        self.key = _tagged_hash("bip324_rekey", self.key)
        self.nonce_counter = 0


# --- BIP 324 cipher core --------------------------------------------------

@dataclass
class BIP324Cipher:
    """BIP 324 packet cipher (encryption + decryption).

    Owns the four FSChaCha20 / FSChaCha20Poly1305 instances (send/recv ×
    L/P), the 16-byte send/recv garbage terminators, and the 32-byte
    session id.  Mirrors the C++ ``BIP324Cipher`` class in
    ``bitcoin-core/src/bip324.h``.

    Construction goes through ``BIP324Cipher.from_secrets(...)`` after
    the ECDH shared secret is known; direct ``__init__`` is used by
    ``V2Transport`` to wire from a ``V2Handshake``.
    """

    send_l: FSChaCha20
    recv_l: FSChaCha20
    send_p: FSChaCha20Poly1305
    recv_p: FSChaCha20Poly1305
    send_garbage_terminator: bytes
    recv_garbage_terminator: bytes
    session_id: bytes

    @classmethod
    def from_secrets(
        cls,
        ecdh_secret: bytes,
        *,
        initiator: bool,
        network: str = "mainnet",
        self_decrypt: bool = False,
    ) -> "BIP324Cipher":
        """Build a cipher from the 32-byte ECDH shared secret.

        ``self_decrypt=True`` swaps send/recv keys; only used by the
        Core packet-vector test harness (``bip324_tests.cpp``) so that a
        single side can encrypt-then-decrypt a packet without knowing
        the other side's private key.  Default is False for production.
        """
        if len(ecdh_secret) != 32:
            raise ValueError("ECDH secret must be 32 bytes")

        salt = b"bitcoin_v2_shared_secret" + _network_magic_bytes(network)
        prk = _hkdf_extract(salt, ecdh_secret)

        # Six independent 32-byte expansions, one per BIP 324 label.
        init_l = _hkdf_expand(prk, b"initiator_L", 32)
        init_p = _hkdf_expand(prk, b"initiator_P", 32)
        resp_l = _hkdf_expand(prk, b"responder_L", 32)
        resp_p = _hkdf_expand(prk, b"responder_P", 32)
        garb_terms_32 = _hkdf_expand(prk, b"garbage_terminators", 32)
        session_id = _hkdf_expand(prk, b"session_id", 32)

        # ``side`` chooses which set of keys is used for sending vs
        # receiving.  See bip324.cpp:Initialize for the truth-table
        # (``side = initiator != self_decrypt``).
        side = bool(initiator) != bool(self_decrypt)

        if side:
            send_l_key, recv_l_key = init_l, resp_l
            send_p_key, recv_p_key = init_p, resp_p
        else:
            send_l_key, recv_l_key = resp_l, init_l
            send_p_key, recv_p_key = resp_p, init_p

        # Garbage terminators are split ``[:16]`` for the initiator's
        # send and ``[16:]`` for the initiator's recv; the responder's
        # send/recv are the mirror image.  The choice keys off
        # ``initiator``, NOT ``side`` — this is independent of the
        # ``self_decrypt`` flip.
        if initiator:
            send_term = garb_terms_32[:GARBAGE_TERMINATOR_LEN]
            recv_term = garb_terms_32[GARBAGE_TERMINATOR_LEN:]
        else:
            send_term = garb_terms_32[GARBAGE_TERMINATOR_LEN:]
            recv_term = garb_terms_32[:GARBAGE_TERMINATOR_LEN]

        return cls(
            send_l=FSChaCha20(send_l_key),
            recv_l=FSChaCha20(recv_l_key),
            send_p=FSChaCha20Poly1305(send_p_key),
            recv_p=FSChaCha20Poly1305(recv_p_key),
            send_garbage_terminator=send_term,
            recv_garbage_terminator=recv_term,
            session_id=session_id,
        )

    # --- packet encrypt / decrypt ----------------------------------------

    def encrypt_packet(
        self, contents: bytes, *, aad: bytes = b"", ignore: bool = False
    ) -> bytes:
        """Encrypt one BIP 324 packet.

        Wire layout:
            enc_length (3 bytes, FSChaCha20 over little-endian u24)
            ciphertext (1 + len(contents) + 16 = HEADER_LEN + len(contents) + tag)
        """
        if len(contents) > 0xFFFFFF:
            raise ValueError("BIP 324 packet contents must be < 2^24 bytes")

        header = bytes([IGNORE_BIT if ignore else 0])
        plaintext = header + contents
        aead_ct = self.send_p.encrypt(aad, plaintext)
        enc_len = self.send_l.crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, "little"))
        return enc_len + aead_ct

    def decrypt_length(self, enc_length: bytes) -> int:
        """Decrypt the 3-byte length prefix.  Advances the recv length cipher."""
        if len(enc_length) != LENGTH_FIELD_LEN:
            raise ValueError(f"length prefix must be {LENGTH_FIELD_LEN} bytes")
        plain = self.recv_l.crypt(enc_length)
        return int.from_bytes(plain, "little")

    def decrypt_contents(
        self, aead_ct: bytes, contents_len: int, *, aad: bytes = b""
    ) -> tuple[bytes, bool] | None:
        """Decrypt the AEAD-encrypted body of a BIP 324 packet.

        ``aead_ct`` MUST have length ``HEADER_LEN + contents_len + 16``
        (header + payload + Poly1305 tag).  ``contents_len`` is the
        plaintext-content length returned by ``decrypt_length``.

        Returns ``(contents, is_decoy)`` on success, or ``None`` on
        authentication failure.
        """
        expected = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        if len(aead_ct) != expected:
            raise ValueError(
                f"AEAD ciphertext length {len(aead_ct)} != expected {expected}"
            )
        plain = self.recv_p.decrypt(aad, aead_ct)
        if plain is None:
            return None
        header_byte = plain[0]
        is_decoy = (header_byte & IGNORE_BIT) != 0
        return plain[HEADER_LEN:], is_decoy


# --- v2 Handshake ---------------------------------------------------------

@dataclass
class V2Handshake:
    """
    BIP 324 handshake state.

    Both sides generate a 32-byte ephemeral secret key, produce a
    64-byte ElligatorSwift-encoded public key via
    ``secp256k1_ellswift_create``, exchange them on the wire, and then
    derive a 32-byte shared secret via ``secp256k1_ellswift_xdh`` with
    the BIP 324 hash function.  The shared secret feeds the BIP 324
    HKDF key schedule; see ``BIP324Cipher.from_secrets``.

    Key material (``_private_key``, ``_aux_rand``) is stored as
    ``bytearray`` so it can be zeroed in-place and released after the
    ECDH completes.  This mirrors ``bitcoin-core/src/bip324.cpp:67-70``
    (``memory_cleanse`` on ecdh_secret, hkdf_32_okm, hkdf, and m_key).
    Python bytes are immutable and cannot be zeroed; bytearrays are not.
    """
    initiator: bool = True
    network: str = "mainnet"
    _private_key: bytearray | None = field(
        default_factory=lambda: bytearray(_generate_secret_key())
    )
    _aux_rand: bytearray | None = field(
        default_factory=lambda: bytearray(os.urandom(32)), repr=False
    )
    _local_eswift: bytes = field(default=b"", repr=False)
    _remote_eswift: bytes = field(default=b"", repr=False)
    _shared_secret: bytes | None = None

    def __post_init__(self):
        if not self._local_eswift:
            self._local_eswift = secp256k1_ellswift_create(
                bytes(self._private_key), bytes(self._aux_rand)
            )

    @property
    def local_pubkey_bytes(self) -> bytes:
        """64-byte ElligatorSwift-encoded public key to send to the peer."""
        return self._local_eswift

    def receive_remote_pubkey(self, remote_eswift: bytes) -> None:
        """Process the peer's 64-byte ElligatorSwift public key."""
        if len(remote_eswift) != 64:
            raise ValueError("Remote ElligatorSwift key must be 64 bytes")
        self._remote_eswift = remote_eswift
        self._derive_shared_secret()
        self._cleanse_key_material()

    def _derive_shared_secret(self) -> None:
        self._shared_secret = secp256k1_ellswift_xdh(
            self._local_eswift,
            self._remote_eswift,
            bytes(self._private_key),
            self.initiator,
        )

    def _cleanse_key_material(self) -> None:
        """Zero and release ephemeral private key and aux randomness.

        Mirrors ``bitcoin-core/src/bip324.cpp:67-70``:
        ``memory_cleanse(ecdh_secret), memory_cleanse(hkdf_32_okm),
        memory_cleanse(&hkdf), m_key = CKey()``.

        Python's allocator may have already copied the bytearray contents
        into intermediate buffers during ECDH; this zeroing is best-effort
        but substantially better than retaining the live secret on the heap
        indefinitely.
        """
        if self._private_key is not None:
            self._private_key[:] = b"\x00" * len(self._private_key)
            self._private_key = None
        if self._aux_rand is not None:
            self._aux_rand[:] = b"\x00" * len(self._aux_rand)
            self._aux_rand = None

    @property
    def shared_secret(self) -> bytes:
        if self._shared_secret is None:
            raise ValueError("Handshake not complete")
        return self._shared_secret

    def derive_session_keys(self) -> tuple[bytes, bytes]:
        """Return ``(send_p_key, recv_p_key)`` derived from the shared secret.

        Compatibility helper retained for legacy callers (the wiring
        regression test in ``test_bip324_wiring.py`` asserts
        ``client.send_cipher.key == server.recv_cipher.key`` etc).  The
        underlying P (contents) keys are exactly what the wiring test
        wants to compare.

        Use ``BIP324Cipher.from_secrets`` for new code.
        """
        if self._shared_secret is None:
            raise ValueError("Handshake not complete")
        salt = b"bitcoin_v2_shared_secret" + _network_magic_bytes(self.network)
        prk = _hkdf_extract(salt, self._shared_secret)
        init_p = _hkdf_expand(prk, b"initiator_P", 32)
        resp_p = _hkdf_expand(prk, b"responder_P", 32)
        if self.initiator:
            return init_p, resp_p
        return resp_p, init_p


# --- v2 Transport ---------------------------------------------------------

@dataclass
class V2Transport:
    """Full BIP 324 v2 encrypted transport session.

    Wraps a :class:`BIP324Cipher` with the legacy ``send_cipher``/
    ``recv_cipher`` :class:`CipherState` view so existing wiring tests
    that compare per-direction keys (:func:`test_bip324_wiring.
    test_negotiate_v2_happy_path`) continue to type-check.

    For sending and receiving packets, callers should use
    :meth:`encrypt_message` / :meth:`decrypt_message` (one-shot, packet
    self-contained) or :meth:`decrypt_length` + :meth:`decrypt_contents`
    (streaming — needed by ``Peer._receive_v2_message`` because the
    payload size is only known after the length cipher decrypts the
    first 3 bytes).
    """

    cipher: BIP324Cipher
    send_cipher: CipherState
    recv_cipher: CipherState

    @classmethod
    def from_handshake(
        cls, handshake: V2Handshake, *, self_decrypt: bool = False
    ) -> "V2Transport":
        cipher = BIP324Cipher.from_secrets(
            handshake.shared_secret,
            initiator=handshake.initiator,
            network=handshake.network,
            self_decrypt=self_decrypt,
        )
        # Re-key the legacy view with the (P) contents-cipher keys so
        # downstream callers that introspect ``send_cipher.key`` /
        # ``recv_cipher.key`` see the property they expect: both sides'
        # initiator_P and responder_P keys match across the connection.
        send_p_key, recv_p_key = handshake.derive_session_keys()
        return cls(
            cipher=cipher,
            send_cipher=CipherState(key=send_p_key),
            recv_cipher=CipherState(key=recv_p_key),
        )

    @classmethod
    def from_secrets(
        cls,
        ecdh_secret: bytes,
        *,
        initiator: bool,
        network: str = "mainnet",
        self_decrypt: bool = False,
    ) -> "V2Transport":
        """Build a transport directly from an ECDH secret.  Used by the
        packet-vector test harness, where the shared secret is read
        from the test vector rather than derived live.
        """
        cipher = BIP324Cipher.from_secrets(
            ecdh_secret,
            initiator=initiator,
            network=network,
            self_decrypt=self_decrypt,
        )
        salt = b"bitcoin_v2_shared_secret" + _network_magic_bytes(network)
        prk = _hkdf_extract(salt, ecdh_secret)
        init_p = _hkdf_expand(prk, b"initiator_P", 32)
        resp_p = _hkdf_expand(prk, b"responder_P", 32)
        if initiator != self_decrypt:
            send_p_key, recv_p_key = init_p, resp_p
        else:
            send_p_key, recv_p_key = resp_p, init_p
        return cls(
            cipher=cipher,
            send_cipher=CipherState(key=send_p_key),
            recv_cipher=CipherState(key=recv_p_key),
        )

    # --- one-shot packet API ---------------------------------------------

    def encrypt_message(
        self,
        payload: bytes,
        *,
        aad: bytes = b"",
        decoy: bool = False,
    ) -> bytes:
        """Encrypt a BIP 324 packet with ``payload`` as contents.

        ``aad`` is the additional-authenticated-data field — used during
        the post-garbage version-packet exchange to bind the received
        garbage into the first packet's MAC.
        """
        return self.cipher.encrypt_packet(payload, aad=aad, ignore=decoy)

    def decrypt_message(
        self, data: bytes, *, aad: bytes = b""
    ) -> tuple[bytes, bool, int]:
        """Decrypt one BIP 324 packet.

        Returns ``(contents, is_decoy, bytes_consumed)``.  Raises
        :class:`ValueError` if the wire frame is too short, and a
        :class:`ValueError` "Authentication failed" if the AEAD tag
        does not validate.
        """
        if len(data) < LENGTH_FIELD_LEN + HEADER_LEN + CHACHA20POLY1305_EXPANSION:
            raise ValueError("Packet too short")
        enc_length = data[:LENGTH_FIELD_LEN]
        contents_len = self.cipher.decrypt_length(enc_length)
        total = (
            LENGTH_FIELD_LEN
            + HEADER_LEN
            + contents_len
            + CHACHA20POLY1305_EXPANSION
        )
        if len(data) < total:
            raise ValueError(f"Need {total} bytes, have {len(data)}")
        aead_ct = data[LENGTH_FIELD_LEN:total]
        result = self.cipher.decrypt_contents(aead_ct, contents_len, aad=aad)
        if result is None:
            raise ValueError("BIP 324 packet authentication failed")
        contents, is_decoy = result
        return contents, is_decoy, total

    # --- streaming API (used by Peer._receive_v2_message) ---------------

    def decrypt_length(self, enc_length: bytes) -> int:
        """Decrypt the 3-byte length prefix; advances the recv L cipher."""
        return self.cipher.decrypt_length(enc_length)

    def decrypt_contents(
        self, aead_ct: bytes, contents_len: int, *, aad: bytes = b""
    ) -> tuple[bytes, bool]:
        """Decrypt the AEAD body; advances the recv P cipher.

        Raises :class:`ValueError` on auth failure (caller in
        ``peer.py`` is responsible for translating that into a peer
        disconnect).
        """
        result = self.cipher.decrypt_contents(aead_ct, contents_len, aad=aad)
        if result is None:
            raise ValueError("BIP 324 packet authentication failed")
        return result

    # --- garbage terminator accessors ------------------------------------

    @property
    def send_garbage_terminator(self) -> bytes:
        return self.cipher.send_garbage_terminator

    @property
    def recv_garbage_terminator(self) -> bytes:
        return self.cipher.recv_garbage_terminator

    @property
    def session_id(self) -> bytes:
        return self.cipher.session_id
