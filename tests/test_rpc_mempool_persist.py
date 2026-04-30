"""
Tests for dumpmempool / savemempool / loadmempool RPC handlers.

These RPCs wrap the existing :class:`Mempool` persistence routines added in
ouroboros@8210ab2 / @ad8ceef (Bitcoin Core compatible mempool.dat format,
``kernel/mempool_persist.cpp``).

Reference:
  * bitcoin-core/src/rpc/mempool.cpp dumpmempool / savemempool
  * bitcoin-core/src/node/mempool_persist.cpp DumpMempool / LoadMempool
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Stub Rust ``sync`` extension before any ouroboros submodule is imported.
# Mirrors tests/test_mempool_persist_core_format.py.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"

    class _StubDB:
        def __init__(self, *a, **kw):
            self._utxos: dict = {}
            self._best_block = (b"\x00" * 32, 100)

        def get_block(self, *a, **kw):
            return None

        def get_block_by_height(self, *a, **kw):
            return None

        def get_best_block(self, *a, **kw):
            return self._best_block

        def get_utxo(self, txid, vout):
            return self._utxos.get((txid, vout))

        def add_utxo(self, txid, vout, value, script_pubkey=b""):
            self._utxos[(txid, vout)] = {
                "value": value,
                "script_pubkey": script_pubkey,
            }

    _mock.PyBlockchainDB = _StubDB
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: True
    sys.modules["sync"] = _mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers (mirror tests/test_mempool_persist_core_format.py)
# ---------------------------------------------------------------------------
class _StubChainDB:
    def __init__(self) -> None:
        self._utxos: dict = {}
        self._best_block = (b"\x00" * 32, 100)

    def add_utxo(self, txid: bytes, vout: int, value: int) -> None:
        self._utxos[(txid, vout)] = {"value": value, "script_pubkey": b""}

    def get_utxo(self, txid: bytes, vout: int):
        return self._utxos.get((txid, vout))

    def get_best_block(self):
        return self._best_block


class _AlwaysOkValidator:
    def __init__(self, db: _StubChainDB | None = None) -> None:
        self.db = db or _StubChainDB()

    def validate_transaction(self, tx, height):
        return True, ""


class _StubNode:
    def __init__(self, data_dir: str, mempool: Mempool, db: _StubChainDB):
        self.data_dir = data_dir
        self.mempool = mempool
        self.db = db


def _make_tx(seed: int, db: _StubChainDB) -> Transaction:
    import hashlib

    prev_txid = bytes([seed]) * 32
    db.add_utxo(prev_txid, 0, 100_000_000)
    inputs = [
        TxIn(
            prev_txid=prev_txid,
            prev_vout=0,
            script_sig=b"\x51",
            sequence=0xFFFFFFFF,
            witness=None,
        )
    ]
    outputs = [TxOut(value=99_990_000, script_pubkey=b"\x76\xa9")]
    tx = Transaction(
        txid=bytes(32),
        version=2,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=False,
    )
    body = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(body).digest()).digest()
    return tx


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rpc_with_mempool(tmp_path):
    from ouroboros.rpc import RPCServer

    db = _StubChainDB()
    mp = Mempool(_AlwaysOkValidator(db), require_standard=False)
    # Add two non-witness txs at height 100 to seed the mempool.
    for seed in (1, 2):
        tx = _make_tx(seed, db)
        ok, _ = mp.add_transaction(tx, height=100)
        assert ok

    data_dir = tmp_path / "datadir"
    data_dir.mkdir()
    node = _StubNode(str(data_dir), mp, db)

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = node
    return rpc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumpmempool_writes_default_path(rpc_with_mempool):
    expected = os.path.join(rpc_with_mempool.node.data_dir, "mempool.dat")
    result = await rpc_with_mempool.rpc_dumpmempool()
    assert result["filename"] == expected
    assert result["txcount"] == 2
    assert os.path.exists(expected)


@pytest.mark.asyncio
async def test_savemempool_aliases_dumpmempool(rpc_with_mempool):
    """Core treats savemempool as an alias of dumpmempool — same payload."""
    out_a = await rpc_with_mempool.rpc_savemempool()
    out_b = await rpc_with_mempool.rpc_dumpmempool()
    assert out_a == out_b


@pytest.mark.asyncio
async def test_dumpmempool_explicit_path(rpc_with_mempool, tmp_path):
    target = tmp_path / "custom-mempool.dat"
    result = await rpc_with_mempool.rpc_dumpmempool(str(target))
    assert result["filename"] == str(target)
    assert target.exists()


@pytest.mark.asyncio
async def test_loadmempool_roundtrip(rpc_with_mempool, tmp_path):
    """Dump → wipe in-memory mempool → load: count must be restored."""
    dump_path = tmp_path / "roundtrip.dat"
    await rpc_with_mempool.rpc_dumpmempool(str(dump_path))

    # Wipe the in-memory mempool by reattaching a fresh one with the same
    # validator (preserves UTXO context).
    mp = rpc_with_mempool.node.mempool
    original_count = len(mp.transactions)
    new_mp = Mempool(mp.validator, require_standard=False)
    rpc_with_mempool.node.mempool = new_mp
    assert len(new_mp.transactions) == 0

    out = await rpc_with_mempool.rpc_loadmempool(str(dump_path))
    assert out["filename"] == str(dump_path)
    assert out["loaded"] == original_count
    assert len(new_mp.transactions) == original_count


@pytest.mark.asyncio
async def test_loadmempool_missing_file_returns_zero(rpc_with_mempool, tmp_path):
    missing = tmp_path / "does-not-exist.dat"
    out = await rpc_with_mempool.rpc_loadmempool(str(missing))
    assert out["loaded"] == 0


@pytest.mark.asyncio
async def test_dumpmempool_no_mempool_raises(tmp_path):
    from fastapi import HTTPException

    from ouroboros.rpc import RPCServer

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = types.SimpleNamespace(data_dir=str(tmp_path), mempool=None)
    with pytest.raises(HTTPException):
        await rpc.rpc_dumpmempool()
