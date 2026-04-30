"""
Tests for the signmessage / verifymessage RPC handlers.

Reference: bitcoin-core/src/rpc/signmessage.cpp and
bitcoin-core/src/common/signmessage.cpp.

The on-the-wire format is a base64-encoded 65-byte compact recoverable
ECDSA signature::

    header(1) || r(32) || s(32)
    header = 27 + recid + (4 if compressed else 0)

The hash signed is::

    SHA256d(VarStr("Bitcoin Signed Message:\\n") || VarStr(message))
"""

from __future__ import annotations

import base64
import hashlib

import pytest


# ---------------------------------------------------------------------------
# Stub-node helpers
# ---------------------------------------------------------------------------


class _StubKey:
    """Minimum surface needed for rpc_signmessage to drive sign_recoverable."""

    def __init__(self, secret: bytes, network: str = "mainnet"):
        from coincurve import PrivateKey

        self._privkey = PrivateKey(secret)
        self.secret = secret
        self.network = network
        self.pubkey = self._privkey.public_key.format(compressed=True)

    def get_p2pkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import base58

        h160 = _hash160(self.pubkey)
        version = b"\x00" if self.network == "mainnet" else b"\x6f"
        return base58.b58encode_check(version + h160).decode()

    def get_p2wpkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import bech32

        h160 = _hash160(self.pubkey)
        hrp = "bc" if self.network == "mainnet" else "tb"
        converted = bech32.convertbits(h160, 8, 5)
        return bech32.bech32_encode(hrp, [0] + converted)

    def get_p2sh_p2wpkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import base58

        h160 = _hash160(self.pubkey)
        redeem_script = b"\x00\x14" + h160
        script_hash = _hash160(redeem_script)
        version = b"\x05" if self.network == "mainnet" else b"\xc4"
        return base58.b58encode_check(version + script_hash).decode()

    def to_wif(self) -> str:
        import base58

        version = b"\x80" if self.network == "mainnet" else b"\xef"
        return base58.b58encode_check(version + self.secret + b"\x01").decode()


class _StubWallet:
    def __init__(self, secret: bytes, network: str = "mainnet"):
        self._key = _StubKey(secret, network)
        self.keys = [{"wif": self._key.to_wif()}]
        self.network = network

    def _get_wallet_key(self, kd):
        return self._key


class _StubNode:
    def __init__(self, secret: bytes, network: str = "mainnet"):
        self.network = network
        self.wallet = _StubWallet(secret, network)


@pytest.fixture
def secret_key() -> bytes:
    # Deterministic 32-byte secret for stable test output.
    return hashlib.sha256(b"ouroboros-signmessage-test").digest()


@pytest.fixture
def rpc_with_wallet(secret_key):
    from ouroboros.rpc import RPCServer

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = _StubNode(secret_key, network="mainnet")
    rpc._current_wallet_name = None
    return rpc


# ---------------------------------------------------------------------------
# Hash helper sanity check
# ---------------------------------------------------------------------------


def test_message_hash_matches_core_formula():
    """_message_hash must equal SHA256d(VarStr(MAGIC) || VarStr(message))."""
    from ouroboros.rpc import _message_hash, _MESSAGE_MAGIC

    msg = "ouroboros-vector"
    magic = _MESSAGE_MAGIC.encode()
    payload = bytes([len(magic)]) + magic + bytes([len(msg)]) + msg.encode()
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    assert _message_hash(msg) == expected


# ---------------------------------------------------------------------------
# Sign / verify roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signmessage_roundtrip_p2pkh(rpc_with_wallet):
    """signmessage(addr, msg) → verifymessage(addr, sig, msg) == True."""
    addr = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    msg = "hello world"

    sig = await rpc_with_wallet.rpc_signmessage(addr, msg)
    assert isinstance(sig, str)

    raw = base64.b64decode(sig, validate=True)
    assert len(raw) == 65
    assert 31 <= raw[0] <= 34  # compressed-pubkey header range

    ok = await rpc_with_wallet.rpc_verifymessage(addr, sig, msg)
    assert ok is True


@pytest.mark.asyncio
async def test_signmessage_via_p2wpkh_address(rpc_with_wallet):
    """ouroboros allows signing by P2WPKH address (the wallet's default
    address type) — verifymessage still validates against the equivalent
    P2PKH legacy address derived from the same key."""
    p2wpkh = rpc_with_wallet.node.wallet._key.get_p2wpkh_address()
    p2pkh = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    msg = "ouroboros-segwit"

    sig = await rpc_with_wallet.rpc_signmessage(p2wpkh, msg)
    ok = await rpc_with_wallet.rpc_verifymessage(p2pkh, sig, msg)
    assert ok is True


@pytest.mark.asyncio
async def test_verifymessage_wrong_message_fails(rpc_with_wallet):
    addr = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    sig = await rpc_with_wallet.rpc_signmessage(addr, "msg-A")
    ok = await rpc_with_wallet.rpc_verifymessage(addr, sig, "msg-B")
    assert ok is False


@pytest.mark.asyncio
async def test_verifymessage_wrong_address_fails(rpc_with_wallet):
    """A different P2PKH address derived from a different key must reject."""
    addr = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    msg = "wrong-addr-test"
    sig = await rpc_with_wallet.rpc_signmessage(addr, msg)

    # Make a totally different key and use its P2PKH address
    other_secret = hashlib.sha256(b"different-key").digest()
    other_key = _StubKey(other_secret)
    other_addr = other_key.get_p2pkh_address()
    assert other_addr != addr

    ok = await rpc_with_wallet.rpc_verifymessage(other_addr, sig, msg)
    assert ok is False


@pytest.mark.asyncio
async def test_verifymessage_rejects_malformed_base64(rpc_with_wallet):
    from fastapi import HTTPException

    addr = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_verifymessage(addr, "@@@notbase64@@@", "x")


@pytest.mark.asyncio
async def test_verifymessage_rejects_segwit_address(rpc_with_wallet):
    """verifymessage is P2PKH-only (matches Core's MessageVerify)."""
    from fastapi import HTTPException

    p2wpkh = rpc_with_wallet.node.wallet._key.get_p2wpkh_address()
    sig = await rpc_with_wallet.rpc_signmessage(p2wpkh, "msg")
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_verifymessage(p2wpkh, sig, "msg")


@pytest.mark.asyncio
async def test_signmessage_unknown_address_raises(rpc_with_wallet):
    from fastapi import HTTPException

    other_addr = _StubKey(hashlib.sha256(b"unknown").digest()).get_p2pkh_address()
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_signmessage(other_addr, "x")
