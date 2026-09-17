"""Snapshot-boot gettxoutsetinfo at the loaded base (QUEUES.md coverage).

After campaign ``import-utxo`` / ``loadtxoutset`` the range-runner calls
gettxoutsetinfo before any window block connects. At rungs 852000 and
875000 that walk timed out (default 900s scan deadline) and the harness
recorded NO-ORACLE-SURFACE with utxo_hash="-1" (empty RPC → python
default height -1) — the range never ran.

The load already folded HASH_SERIALIZED + totals. gettxoutsetinfo at
that same tip must report height == base and bestblock == base hash
without a second coins-DB walk.

Control: this file. Negative: after load, stream_utxo_txid_groups
raises; the RPC still returns the snapshot-base surface (cache hit).
Reverting the cache seed in load_snapshot / import-utxo fails that.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from ouroboros.muhash import coin_element
from ouroboros.rpc import RPCServer
from ouroboros.snapshot import (
    HashWriter,
    SnapshotManager,
    get_assumeutxo_data,
)


_REPO = Path(__file__).resolve().parents[1]


@dataclass
class _UTXOEntry:
    txid: bytes
    vout: int
    amount: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool


class _StubDB:
    def __init__(self) -> None:
        self.utxos: list[_UTXOEntry] = []
        self.best_hash: bytes = bytes(32)
        self.best_height: int = 0

    def get_best_block(self) -> tuple[bytes, int]:
        return self.best_hash, self.best_height

    def utxo_count(self) -> int:
        return len(self.utxos)

    def iter_utxos(self):
        return iter(self.utxos)

    def add_utxo_raw(self, *, txid, vout, amount, script_pubkey, height, is_coinbase):
        self.utxos.append(
            _UTXOEntry(
                txid=txid,
                vout=vout,
                amount=amount,
                script_pubkey=bytes(script_pubkey),
                height=height,
                is_coinbase=is_coinbase,
            )
        )

    def update_best_block(self, block_hash: bytes, height: int) -> None:
        self.best_hash = block_hash
        self.best_height = height


def _p2pkh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def _make_rpc(db: _StubDB, sm: SnapshotManager | None = None) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    node.network = "mainnet"
    node.snapshot_manager = sm
    rpc.node = node
    rpc._current_wallet_name = None
    rpc.block_submission_paused = False
    return rpc


def _one_coin() -> _UTXOEntry:
    return _UTXOEntry(
        txid=b"\xab" * 32,
        vout=0,
        amount=12345,
        script_pubkey=_p2pkh(b"\xcd" * 20),
        height=100_000,
        is_coinbase=False,
    )


def _digest_for(coin: _UTXOEntry) -> bytes:
    h = HashWriter()
    h.update(
        coin_element(
            txid=coin.txid,
            vout=coin.vout,
            height=coin.height,
            is_coinbase=coin.is_coinbase,
            amount=coin.amount,
            script_pubkey=coin.script_pubkey,
        )
    )
    return h.digest()


def _load_patched_snapshot(tmp_path, monkeypatch):
    """Dump/load a 1-coin snapshot at mainnet@840k with a matching commitment."""
    from ouroboros import snapshot as snapshot_mod

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None
    coin = _one_coin()
    digest = _digest_for(coin)

    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    src.utxos.append(coin)
    snap_path = tmp_path / "base.dat"
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(str(snap_path))

    patched = snapshot_mod.AssumeutxoData(
        height=au.height,
        block_hash=au.block_hash,
        hash_serialized=digest,
        chain_tx_count=au.chain_tx_count,
        base_header=au.base_header,
        chainwork_hex=au.chainwork_hex,
    )
    monkeypatch.setattr(
        snapshot_mod,
        "_MAINNET_ASSUMEUTXO",
        [patched if d.height == au.height else d for d in snapshot_mod._MAINNET_ASSUMEUTXO],
    )

    dst = _StubDB()
    sm = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    sm.load_snapshot(str(snap_path))
    return sm, dst, digest, au, coin


@pytest.mark.asyncio
async def test_loadtxoutset_then_gettxoutsetinfo_reports_height_eq_base(
    tmp_path,
    monkeypatch,
) -> None:
    sm, dst, digest, au, _coin = _load_patched_snapshot(tmp_path, monkeypatch)
    assert sm.snapshot_loaded
    assert dst.best_height == au.height
    assert dst.best_hash == au.block_hash

    rpc = _make_rpc(dst, sm)
    res = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_3")

    assert res["height"] == au.height
    assert isinstance(res["height"], int)
    assert res["bestblock"] == au.block_hash[::-1].hex()
    assert res["hash_serialized_3"] == digest[::-1].hex()
    assert len(res["hash_serialized_3"]) == 64
    assert res["txouts"] == 1
    assert res["transactions"] == 1


@pytest.mark.asyncio
async def test_snapshot_base_gettxoutsetinfo_does_not_walk_coins(
    tmp_path,
    monkeypatch,
) -> None:
    sm, dst, digest, au, _coin = _load_patched_snapshot(tmp_path, monkeypatch)

    def _boom(*_a, **_k):
        raise RuntimeError("coins walk must not run at snapshot base")

    monkeypatch.setattr("ouroboros.snapshot.stream_utxo_txid_groups", _boom)

    rpc = _make_rpc(dst, sm)
    res = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_3")
    assert res["height"] == au.height
    assert res["bestblock"] == au.block_hash[::-1].hex()
    assert res["hash_serialized_3"] == digest[::-1].hex()


def test_snapshot_base_cache_survives_new_manager_from_disk(
    tmp_path,
    monkeypatch,
) -> None:
    sm, dst, digest, au, _coin = _load_patched_snapshot(tmp_path, monkeypatch)
    cache_path = sm.get_snapshot_chainstate_dir() / "txoutset_cache.json"
    assert cache_path.is_file(), "load_snapshot must persist the base surface"

    sm2 = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    cached = sm2.get_cached_txoutset()
    assert cached is not None
    assert cached.height == au.height
    assert cached.best_block == au.block_hash
    assert cached.hash_serialized == digest
    assert cached.txouts == 1


@pytest.mark.asyncio
async def test_snapshot_base_cache_misses_after_tip_moves(
    tmp_path,
    monkeypatch,
) -> None:
    sm, dst, digest, au, _coin = _load_patched_snapshot(tmp_path, monkeypatch)
    dst.update_best_block(b"\x11" * 32, au.height + 1)

    walked = {"n": 0}

    def _count(db, on_group):
        walked["n"] += 1
        groups: dict[bytes, dict[int, _UTXOEntry]] = {}
        for u in db.iter_utxos():
            groups.setdefault(u.txid, {})[u.vout] = u
        for tid, outputs in groups.items():
            on_group(tid, outputs)
        return len(groups), max((len(g) for g in groups.values()), default=0)

    monkeypatch.setattr("ouroboros.snapshot.stream_utxo_txid_groups", _count)

    rpc = _make_rpc(dst, sm)
    res = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_3")
    assert walked["n"] == 1
    assert res["height"] == au.height + 1
    assert res["hash_serialized_3"] != digest[::-1].hex() or res["height"] != au.height
