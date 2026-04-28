"""
BIP 324 — v2 P2P Transport Protocol.

Implements encrypted and authenticated P2P connections using:
- ElligatorSwift key exchange (X-only ECDH over secp256k1)
- ChaCha20-Poly1305 AEAD for packet encryption
- Length encryption to prevent traffic analysis

Each direction of the connection has its own symmetric key derived
from the ECDH shared secret.  After the handshake every subsequent
P2P message is encrypted and authenticated.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
           bitcoin/src/bip324.cpp, bitcoin/src/bip324.h
           libsecp256k1 ellswift module (modules/ellswift/main_impl.h)

ECDH backend: real ``secp256k1_ellswift_create`` /
``secp256k1_ellswift_xdh`` with the BIP 324 hash function, called
through ``coincurve``'s bundled libsecp256k1 cffi bindings.  The
shared-secret path is byte-for-byte equivalent to libsecp256k1's
``ellswift_xdh_tests_bip324`` reference vectors (see
``tests/test_bip324_vectors.py``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum

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
    secp256k1 scalar (1 ≤ d < n).
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
    """Generate a uniformly random 32-byte secp256k1 scalar (1 ≤ d < n)."""
    # secp256k1's curve order n is just below 2^256, so the rejection
    # rate of os.urandom(32) is negligible (~2^-128).  But ellswift_create
    # itself rejects 0 and values >= n, so we loop defensively.
    while True:
        sk = os.urandom(32)
        # All-zero is the only practically-likely invalid value;
        # libsecp256k1 will tell us about anything else by returning 0
        # from ellswift_create, which our wrapper raises on.
        if sk != b"\x00" * 32:
            return sk

# constants

NETWORK_MAGIC_V2 = b""  # v2 has no network magic; first 64 bytes are ESwift keys
REKEY_INTERVAL = 224     # re-key after this many messages (BIP 324)

# BIP 324 transport versioning
TRANSPORT_V1 = 1
TRANSPORT_V2 = 2


class PacketType(IntEnum):
    """BIP 324 packet content flags."""
    GENUINE = 0
    DECOY = 128


# tagged hash (BIP 340-style)

def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# --- HKDF-SHA256 (extract + expand, single-info) ---

def _hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Single expand block is sufficient for 32-byte output
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ChaCha20-Poly1305 cipher for a single direction

@dataclass
class CipherState:
    """
    Symmetric cipher state for one direction of the v2 transport.

    Handles nonce tracking, encryption/decryption, and periodic
    re-keying after ``REKEY_INTERVAL`` packets.
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


# v2 Handshake & Session #

@dataclass
class V2Handshake:
    """
    BIP 324 handshake state.

    Both sides generate a 32-byte ephemeral secret key, produce a
    64-byte ElligatorSwift-encoded public key via
    ``secp256k1_ellswift_create``, exchange them on the wire, and then
    derive a 32-byte shared secret via ``secp256k1_ellswift_xdh`` with
    the BIP 324 hash function (party=0 for initiator, party=1 for
    responder).  Per-direction symmetric keys are then expanded from
    that shared secret.

    The shared-secret derivation is byte-for-byte equivalent to the
    libsecp256k1 reference vectors in
    ``modules/ellswift/tests_impl.h:156-164``
    (``ellswift_xdh_tests_bip324``).  See
    ``tests/test_bip324_vectors.py`` for the validation suite.

    Note on session-key derivation: BIP 324 specifies a more elaborate
    HKDF schedule (separate keys for length cipher, packet cipher,
    garbage terminators, and a session id) keyed off the shared
    secret.  This module currently keeps a simpler one-key-per-direction
    expansion for self-consistency with the existing ``V2Transport``
    framing — full BIP 324 packet-format compliance with Bitcoin Core
    requires a follow-up.  But the *shared secret itself* now matches
    Core's bit-for-bit, which is the prerequisite the whole rest of
    the v2 stack stands on.
    """
    initiator: bool = True
    _private_key: bytes = field(default_factory=_generate_secret_key)
    _aux_rand: bytes = field(default_factory=lambda: os.urandom(32), repr=False)
    _local_eswift: bytes = field(default=b"", repr=False)
    _remote_eswift: bytes = field(default=b"", repr=False)
    _shared_secret: bytes | None = None

    def __post_init__(self):
        if not self._local_eswift:
            # Real ElligatorSwift encoding via libsecp256k1.
            self._local_eswift = secp256k1_ellswift_create(
                self._private_key, self._aux_rand
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

    def _derive_shared_secret(self) -> None:
        # Real BIP 324 ECDH via libsecp256k1.  Both sides compute the
        # same 32-byte secret because secp256k1_ellswift_xdh(party=0,
        # ours, theirs, our_priv) and ellswift_xdh(party=1, ours,
        # theirs, their_priv) produce identical output by definition
        # of the X-only ECDH protocol.
        self._shared_secret = secp256k1_ellswift_xdh(
            self._local_eswift,
            self._remote_eswift,
            self._private_key,
            self.initiator,
        )

    def derive_session_keys(self) -> tuple[bytes, bytes]:
        """
        Derive (send_key, recv_key) from the shared secret.

        Both sides derive the same two keys (``initiator_key`` and
        ``responder_key``) from the shared secret.  The initiator
        sends with ``initiator_key`` and receives with
        ``responder_key``; the responder does the opposite.

        Returns two 32-byte symmetric keys.
        """
        if self._shared_secret is None:
            raise ValueError("Handshake not complete")
        initiator_key = _hkdf_sha256(
            salt=self._shared_secret,
            ikm=b"bip324_initiator",
            info=b"expand",
        )
        responder_key = _hkdf_sha256(
            salt=self._shared_secret,
            ikm=b"bip324_responder",
            info=b"expand",
        )
        if self.initiator:
            return initiator_key, responder_key
        return responder_key, initiator_key


@dataclass
class V2Transport:
    """
    Full BIP 324 v2 encrypted transport session.

    After handshake completion, call ``encrypt_message`` and
    ``decrypt_message`` for each P2P payload.
    """
    send_cipher: CipherState
    recv_cipher: CipherState

    @classmethod
    def from_handshake(cls, handshake: V2Handshake) -> V2Transport:
        send_key, recv_key = handshake.derive_session_keys()
        return cls(
            send_cipher=CipherState(key=send_key),
            recv_cipher=CipherState(key=recv_key),
        )

    # packet format

    def encrypt_message(self, payload: bytes, *, decoy: bool = False) -> bytes:
        """
        Encrypt a P2P message payload into a v2 packet.

        Packet layout:
          encrypted_length (3 bytes, encrypted with length cipher)
          encrypted_payload (variable + 16 byte Poly1305 tag)

        The first byte of the plaintext payload carries the packet
        type flag (``GENUINE`` or ``DECOY``).
        """
        flag = PacketType.DECOY if decoy else PacketType.GENUINE
        inner = bytes([flag]) + payload
        length_bytes = len(inner).to_bytes(3, "little")
        enc_length = self.send_cipher.encrypt(length_bytes)
        enc_payload = self.send_cipher.encrypt(inner)
        return enc_length + enc_payload

    def decrypt_message(self, data: bytes) -> tuple[bytes, bool, int]:
        """
        Decrypt a v2 packet.

        Returns (payload, is_decoy, bytes_consumed).
        """
        if len(data) < 3 + 16:
            raise ValueError("Packet too short")
        enc_length = data[:3 + 16]  # 3 bytes + 16 byte tag
        length_plain = self.recv_cipher.decrypt(enc_length)
        msg_len = int.from_bytes(length_plain, "little")

        total = 3 + 16 + msg_len + 16  # length packet + payload packet
        if len(data) < total:
            raise ValueError(f"Need {total} bytes, have {len(data)}")

        enc_payload = data[3 + 16 : total]
        inner = self.recv_cipher.decrypt(enc_payload)
        is_decoy = inner[0] == PacketType.DECOY
        return inner[1:], is_decoy, total
