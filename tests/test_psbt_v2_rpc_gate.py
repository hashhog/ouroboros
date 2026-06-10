"""PSBT-v2 default-off RPC gate (Core parity, 2026-06-09).

Bitcoin Core supports ONLY PSBT v0 (psbt.h:80 PSBT_HIGHEST_VERSION = 0): a
PSBT whose global 0xFB version record exceeds 0 fails decode in every
PSBT-accepting RPC with code -22 and message exactly
``TX decode failed Unsupported version number: iostream error``
(confirmed byte-identical against the v31.99.0 oracle on a throwaway
regtest, 2026-06-09). ouroboros keeps its full BIP-370 v2 implementation in
``ouroboros.psbt`` (tests/test_fix63_psbt_v2_status.py) but the RPC layer
rejects v2+ by default; ``OUROBOROS_PSBT_V2=1`` restores v2 acceptance.

These tests call the RPC handlers directly (no network) on a mock node.
"""

import asyncio
import base64

import pytest

from ouroboros.rpc import JSONRPCResponse, RPCServer

# Minimal BIP-370 v2 blob: magic + globals {0x02 tx_version=2,
# 0x04 input_count=0, 0x05 output_count=0, 0xFB psbt_version=2} + separator.
# Same bytes the oracle probe used.
V2_BLOB = "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA=="
# The same blob WITHOUT the 0xFB record: a "v0" PSBT carrying no unsigned
# transaction -> Core: -22 "No unsigned transaction was provided".
NO_VERSION_BLOB = "cHNidP8BAgQCAAAAAQQBAAEFAQAA"

V2_REJECT_MSG = "TX decode failed Unsupported version number: iostream error"
NO_TX_MSG = "TX decode failed No unsigned transaction was provided: iostream error"


class MockDB:
    def get_block(self, *a, **kw):
        return None

    def get_block_by_height(self, *a, **kw):
        return None

    def get_best_block(self, *a, **kw):
        return (b"\x00" * 32, 0)

    def get_utxo(self, *a, **kw):
        return None


class MockNode:
    def __init__(self):
        self.db = MockDB()
        self.network = "regtest"
        self.wallet = None


@pytest.fixture
def server():
    return RPCServer(MockNode(), port=0, rate_limit=False)


@pytest.fixture
def default_env(monkeypatch):
    monkeypatch.delenv("OUROBOROS_PSBT_V2", raising=False)


@pytest.fixture
def optin_env(monkeypatch):
    monkeypatch.setenv("OUROBOROS_PSBT_V2", "1")


def _v0_blob() -> str:
    """A well-formed v0 PSBT (1-in, 1-out unsigned tx)."""
    from ouroboros.database import Transaction, TxIn, TxOut
    from ouroboros.psbt import PSBT

    tx = Transaction(
        txid=b"\x00" * 32,
        version=2,
        inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                     script_sig=b"", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=10_000,
                       script_pubkey=b"\x00\x14" + b"\x22" * 20)],
        locktime=0,
    )
    psbt = PSBT.from_transaction(tx)
    return base64.b64encode(psbt.serialize()).decode("ascii")


def _assert_v2_reject(resp):
    assert isinstance(resp, JSONRPCResponse), f"expected error, got {resp!r}"
    assert resp.error is not None
    assert resp.error["code"] == -22
    assert resp.error["message"] == V2_REJECT_MSG


class TestDefaultRejectsV2:
    """Default config (flag unset): every PSBT surface rejects v2 like Core."""

    def test_decodepsbt(self, server, default_env):
        _assert_v2_reject(asyncio.run(server.rpc_decodepsbt(V2_BLOB)))

    def test_analyzepsbt(self, server, default_env):
        _assert_v2_reject(asyncio.run(server.rpc_analyzepsbt(V2_BLOB)))

    def test_combinepsbt(self, server, default_env):
        _assert_v2_reject(
            asyncio.run(server.rpc_combinepsbt([V2_BLOB, V2_BLOB]))
        )

    def test_finalizepsbt(self, server, default_env):
        _assert_v2_reject(asyncio.run(server.rpc_finalizepsbt(V2_BLOB)))

    def test_utxoupdatepsbt(self, server, default_env):
        _assert_v2_reject(asyncio.run(server.rpc_utxoupdatepsbt(V2_BLOB)))

    def test_joinpsbts(self, server, default_env):
        _assert_v2_reject(
            asyncio.run(server.rpc_joinpsbts([V2_BLOB, V2_BLOB]))
        )

    def test_walletprocesspsbt(self, server, default_env):
        _assert_v2_reject(asyncio.run(server.rpc_walletprocesspsbt(V2_BLOB)))

    def test_no_unsigned_tx_control(self, server, default_env):
        # Control blob (no 0xFB record): the missing-unsigned-tx error fires
        # instead — also byte-identical to the oracle.
        resp = asyncio.run(server.rpc_decodepsbt(NO_VERSION_BLOB))
        assert isinstance(resp, JSONRPCResponse)
        assert resp.error["code"] == -22
        assert resp.error["message"] == NO_TX_MSG

    def test_v0_still_decodes(self, server, default_env):
        resp = asyncio.run(server.rpc_decodepsbt(_v0_blob()))
        assert isinstance(resp, dict)
        assert resp["tx"]["version"] == 2


class TestOptInRestoresV2:
    """OUROBOROS_PSBT_V2=1 restores the full BIP-370 RPC behavior."""

    def test_decodepsbt_accepts_v2(self, server, optin_env):
        resp = asyncio.run(server.rpc_decodepsbt(V2_BLOB))
        assert isinstance(resp, dict)
        assert resp.get("psbt_version") == 2

    def test_analyzepsbt_accepts_v2(self, server, optin_env):
        resp = asyncio.run(server.rpc_analyzepsbt(V2_BLOB))
        assert isinstance(resp, dict)
        assert "next" in resp

    def test_v0_unaffected(self, server, optin_env):
        resp = asyncio.run(server.rpc_decodepsbt(_v0_blob()))
        assert isinstance(resp, dict)


class TestLibraryUngated:
    """The psbt.py library keeps full v2 support regardless of the flag."""

    def test_library_roundtrip_default_env(self, default_env):
        from ouroboros.psbt import PSBT, PSBT_HIGHEST_VERSION

        assert PSBT_HIGHEST_VERSION >= 2
        psbt = PSBT.from_base64(V2_BLOB)
        assert psbt.version == 2
        assert PSBT.from_base64(psbt.to_base64()).version == 2
