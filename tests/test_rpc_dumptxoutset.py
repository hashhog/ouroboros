"""Tests for the ``dumptxoutset`` RPC handler -- in particular the new
``rollback`` mode added to mirror Bitcoin Core's
``rpc/blockchain.cpp::dumptxoutset`` (27.x semantics).

Three operating modes:
- ``type="latest"`` (or empty): dump current tip's UTXO set.
- ``type="rollback"`` (no explicit height): pick the highest assumeutxo
  entry that is ``<=`` current tip; temporarily roll back, dump, restore.
- ``options={"rollback": <height|hash>}``: roll back to a specific
  height (int) or display-order hex hash; dump; then put the chain back.

The rollback dance uses ``invalidate_block`` + ``reconsider_block``
(Core's ``TemporaryRollback`` pattern).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from ouroboros.rpc import RPCServer
from ouroboros.snapshot import SnapshotManager, get_assumeutxo_data  # noqa: I001


# ---------------------------------------------------------------------------
# In-memory stub DB. Mirrors the ``_StubDB`` from ``test_snapshot.py`` plus
# the chain-tip / invalidate / reconsider primitives we drive from rpc.
# ---------------------------------------------------------------------------


@dataclass
class _UTXOEntry:
    txid: bytes
    vout: int
    amount: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool


class _RustDBStub:
    """Stand-in for ``sync.PyBlockchainDB``. Records calls so tests can
    assert the rollback dance fired.

    Models the production behaviour of ``invalidate_block`` /
    ``reconsider_block`` / ``reactivate_best_chain``: invalidate
    disconnects (best tip drops, but block-tree entries remain because
    the real DB keeps body+metadata in BLOCKS_CF/BLOCK_INDEX_CF after
    disconnect). reactivate_best_chain walks back up to the highest
    indexed leaf with valid metadata.
    """

    def __init__(self, parent):
        self._parent = parent
        self.invalidate_calls: list[bytes] = []
        self.reconsider_calls: list[bytes] = []
        self.reactivate_calls: int = 0
        # Mirror of BLOCK_INDEX_CF: maps height -> hash for ALL blocks the
        # DB has ever seen, even if disconnected. Distinct from
        # _StubDB.chain (which models the active chain).
        self._index: dict[int, bytes] = {}
        # Mirror of BLOCK_INDEX_CF status: blocks marked invalid are
        # excluded from the reactivation scan.
        self._invalid: set[int] = set()
        # Toggle to simulate a partial reactivation (e.g. for the
        # "stranded mid-walk" test).
        self.fail_reactivate_at: int | None = None

    def _seed_index(self) -> None:
        """Snapshot the current active chain into _index. Called on
        first invalidate so the stub remembers the leaf we were at."""
        if not self._index:
            self._index = dict(self._parent.chain)

    def invalidate_block(self, block_hash: bytes) -> int:
        if len(block_hash) != 32:
            raise ValueError("block_hash must be 32 bytes")
        self.invalidate_calls.append(bytes(block_hash))

        self._seed_index()

        # Find which height this hash sits at (it was looked up as the
        # *child* of the rollback target, so disconnect everything from
        # that height up to the current tip).
        target_height: int | None = None
        for h, hashbytes in self._parent.chain.items():
            if hashbytes == bytes(block_hash):
                target_height = h
                break
        if target_height is None:
            raise RuntimeError("block not found")
        # Disconnect: drop chain entries from target_height onwards (the
        # active chain shrinks). The block-tree _index keeps them so
        # reactivate_best_chain can find them.
        for h in sorted(self._parent.chain.keys()):
            if h >= target_height:
                self._parent.chain.pop(h, None)
                self._invalid.add(h)
        # Update best block to parent of target.
        new_tip_height = target_height - 1
        if new_tip_height < 0:
            raise RuntimeError("Cannot invalidate genesis block")
        self._parent.best_height = new_tip_height
        self._parent.best_hash = self._parent.chain[new_tip_height]
        return new_tip_height

    def reconsider_block(self, block_hash: bytes) -> int:
        if len(block_hash) != 32:
            raise ValueError("block_hash must be 32 bytes")
        self.reconsider_calls.append(bytes(block_hash))
        # Clear the FAILED flags on the target and its descendants, but
        # don't move best_block — that's reactivate_best_chain's job.
        self._invalid.clear()
        return self._parent.best_height

    def reactivate_best_chain(self) -> int:
        """Walk forward from current best_height through _index,
        re-activating blocks until we hit either the highest indexed
        height or a still-invalid block. Mirrors the Rust impl's
        find-leaf + walk-up algorithm."""
        self.reactivate_calls += 1
        if not self._index:
            # Never invalidated; nothing to do.
            return self._parent.best_height
        max_indexed = max(self._index.keys())
        # Walk up height by height, restoring chain entries.
        h = self._parent.best_height
        while h < max_indexed:
            next_h = h + 1
            if next_h in self._invalid:
                break
            if next_h not in self._index:
                break
            if self.fail_reactivate_at is not None and next_h == self.fail_reactivate_at:
                break
            self._parent.chain[next_h] = self._index[next_h]
            self._parent.best_height = next_h
            self._parent.best_hash = self._index[next_h]
            h = next_h
        return self._parent.best_height


class _StubDB:
    def __init__(self) -> None:
        self.utxos: list[_UTXOEntry] = []
        self.chain: dict[int, bytes] = {}  # height -> internal-order hash
        self.best_hash: bytes = bytes(32)
        self.best_height: int = 0
        self._db = _RustDBStub(self)
        self._cached_tip = None

    # ------------------------------------------------------------------
    # Snapshot-side surface (used by SnapshotManager)
    # ------------------------------------------------------------------
    def get_best_block(self) -> tuple[bytes, int]:
        return self.best_hash, self.best_height

    def utxo_count(self) -> int:
        return len(self.utxos)

    def iter_utxos(self):
        return iter(self.utxos)

    def add_utxo_raw(self, *, txid, vout, amount, script_pubkey, height, is_coinbase):
        self.utxos.append(_UTXOEntry(
            txid=txid, vout=vout, amount=amount,
            script_pubkey=bytes(script_pubkey),
            height=height, is_coinbase=is_coinbase,
        ))

    def update_best_block(self, block_hash: bytes, height: int) -> None:
        self.best_hash = block_hash
        self.best_height = height

    # ------------------------------------------------------------------
    # RPC-side surface (used by rpc_dumptxoutset)
    # ------------------------------------------------------------------
    def get_block_hash_by_height(self, height: int) -> bytes | None:
        return self.chain.get(height)

    def has_block_hash(self, block_hash: bytes) -> bool:
        return bytes(block_hash) in self.chain.values()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _p2pkh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def _make_db_with_chain(network: str = "mainnet", tip_height: int = 5) -> _StubDB:
    """Build a stub DB with a synthetic chain of ``tip_height + 1`` blocks
    (heights 0..tip_height, deterministic hashes) and a few UTXOs. The
    block at the assumeutxo entry's height is anchored to the published
    blockhash so SnapshotManager.load_snapshot's strict gate would
    accept it (we run with strict=False in tests, but the dump-side
    needs a recognised hash for the read-back round-trip)."""
    db = _StubDB()
    for h in range(tip_height + 1):
        # Deterministic, unique 32-byte hash per height.
        db.chain[h] = (h.to_bytes(4, "little") + b"\x00" * 28)
    db.best_height = tip_height
    db.best_hash = db.chain[tip_height]

    # Two UTXOs so dump_snapshot has something to write.
    db.utxos.append(_UTXOEntry(
        txid=b"\xaa" * 32, vout=0, amount=50_000_000,
        script_pubkey=_p2pkh(b"\x01" * 20),
        height=2, is_coinbase=True,
    ))
    db.utxos.append(_UTXOEntry(
        txid=b"\xbb" * 32, vout=1, amount=25_000_000,
        script_pubkey=_p2pkh(b"\x02" * 20),
        height=3, is_coinbase=False,
    ))
    return db


def _make_rpc(db: _StubDB, *, network: str = "mainnet", tmp_path) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    node.network = network
    node.snapshot_manager = SnapshotManager(db, network, str(tmp_path / "snap-cs"))
    rpc.node = node
    rpc._current_wallet_name = None
    return rpc


# ---------------------------------------------------------------------------
# Latest mode (current behaviour).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_latest_default(tmp_path) -> None:
    db = _make_db_with_chain()
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "utxo-latest.dat"

    res = await rpc.rpc_dumptxoutset(str(out_path))

    assert res["coins_written"] == len(db.utxos)
    assert res["base_height"] == db.best_height
    assert os.path.exists(out_path)
    # latest mode does NOT trigger the rollback dance.
    assert "rollback_height" not in res
    assert db._db.invalidate_calls == []
    assert db._db.reconsider_calls == []


@pytest.mark.asyncio
async def test_dumptxoutset_latest_explicit(tmp_path) -> None:
    db = _make_db_with_chain()
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "utxo-latest-explicit.dat"

    res = await rpc.rpc_dumptxoutset(str(out_path), type="latest")
    assert res["coins_written"] == len(db.utxos)
    assert "rollback_height" not in res


@pytest.mark.asyncio
async def test_dumptxoutset_rejects_existing_path(tmp_path) -> None:
    db = _make_db_with_chain()
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "exists.dat"
    out_path.write_text("hi")

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path))
    assert "already exists" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dumptxoutset_rejects_unknown_type(tmp_path) -> None:
    db = _make_db_with_chain()
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "u.dat"

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path), type="banana")
    assert "Invalid snapshot type" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dumptxoutset_rejects_type_rollback_with_other_option(tmp_path) -> None:
    db = _make_db_with_chain()
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "u.dat"

    # Core 27.x rule: you can't set both type=latest AND options.rollback.
    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(
            str(out_path), type="latest", options={"rollback": 2}
        )
    assert "rollback option" in str(excinfo.value).lower() or \
           "with rollback" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Explicit rollback by height.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_by_height(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=5)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "utxo-rollback-h.dat"
    target = 3
    expected_child_hash = db.chain[target + 1]
    original_tip = db.best_height

    res = await rpc.rpc_dumptxoutset(
        str(out_path), options={"rollback": target}
    )

    assert res["coins_written"] == len(db.utxos)
    assert res["rollback_height"] == target
    assert res["original_tip_height"] == original_tip
    # rollback_hash is the display-order hash of the rollback target.
    # We snapshot it before the chain dict mutation in the rollback dance.
    assert isinstance(res["rollback_hash"], str)
    assert len(res["rollback_hash"]) == 64

    # invalidate was called exactly once on the child of the target.
    assert len(db._db.invalidate_calls) == 1
    assert db._db.invalidate_calls[0] == expected_child_hash
    # reconsider was called exactly once on the same hash (TemporaryRollback dtor).
    assert db._db.reconsider_calls == [expected_child_hash]
    # reactivate_best_chain was invoked after reconsider (the new fix).
    assert db._db.reactivate_calls == 1

    # Dump landed at the rolled-back height.
    assert res["base_height"] == target
    # Reactivation walked the chain back up to the original tip.
    assert res["chain_restored"] is True
    assert db.best_height == original_tip
    assert db.best_hash == db.chain[original_tip]


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_height_above_tip_rejected(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=4)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "above-tip.dat"

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": 99})
    assert "after current tip" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_negative_height_rejected(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=4)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "neg.dat"

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": -1})
    assert "negative" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_equals_tip_no_dance(tmp_path) -> None:
    """Rolling back to the current tip is a no-op rollback dance: dump
    runs but invalidate/reconsider never fire."""
    db = _make_db_with_chain(tip_height=5)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "tip.dat"

    res = await rpc.rpc_dumptxoutset(
        str(out_path), options={"rollback": db.best_height}
    )

    assert res["coins_written"] == len(db.utxos)
    assert res["rollback_height"] == db.best_height
    assert db._db.invalidate_calls == []
    assert db._db.reconsider_calls == []


# ---------------------------------------------------------------------------
# Rollback by hash.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_by_hash_display_order(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=5)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "by-hash.dat"

    target_height = 2
    target_hash_internal = db.chain[target_height]
    target_hash_display = target_hash_internal[::-1].hex()
    expected_child_hash = db.chain[target_height + 1]

    res = await rpc.rpc_dumptxoutset(
        str(out_path), options={"rollback": target_hash_display}
    )

    assert res["rollback_height"] == target_height
    assert res["rollback_hash"] == target_hash_display
    # The hash that gets invalidated is the *child* — height target+1.
    assert db._db.invalidate_calls == [expected_child_hash]
    assert db._db.reconsider_calls == [expected_child_hash]


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_unknown_hash(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=4)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "u.dat"

    bogus = ("ff" * 32)
    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": bogus})
    msg = str(excinfo.value).lower()
    assert "block not found" in msg or "rollback hash" in msg


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_invalid_hash_string(tmp_path) -> None:
    db = _make_db_with_chain(tip_height=4)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "u.dat"

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(
            str(out_path), options={"rollback": "deadbeef"}  # not 64 hex chars
        )
    assert "invalid rollback hash" in str(excinfo.value).lower() or \
           "32 bytes" in str(excinfo.value).lower() or \
           "rollback hash" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Auto rollback (type=rollback, no explicit height).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_auto_picks_highest_assumeutxo_below_tip(
    tmp_path,
) -> None:
    """``type='rollback'`` without an explicit height/hash must select the
    highest published assumeutxo height that is ``<=`` current tip.
    Mirrors Core's ``GetParams().GetAvailableSnapshotHeights()`` +
    ``std::max_element`` block (rpc/blockchain.cpp:3122-3125)."""
    # Mainnet assumeutxo heights: 840k / 880k / 910k / 935k.
    # Stub a chain whose tip is 900_000 — only 840k and 880k are eligible.
    db = _make_db_with_chain(tip_height=2)  # baseline; we override below
    db.chain.clear()
    # Plant just the heights we need (genesis 0, tip 900_000, and the
    # mainnet assumeutxo entries 840k and 880k).
    db.chain[0] = b"\x00" * 32
    au_840 = get_assumeutxo_data("mainnet", 840_000)
    au_880 = get_assumeutxo_data("mainnet", 880_000)
    assert au_840 is not None and au_880 is not None

    db.chain[840_000] = au_840.block_hash
    db.chain[880_000] = au_880.block_hash
    # Plant the child of 880k so invalidate_block can find it.
    child_880001 = b"\xaa" + b"\x00" * 31
    db.chain[880_001] = child_880001
    db.chain[900_000] = b"\xbb" + b"\x00" * 31
    db.best_height = 900_000
    db.best_hash = db.chain[900_000]

    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "auto.dat"

    res = await rpc.rpc_dumptxoutset(str(out_path), type="rollback")

    assert res["rollback_height"] == 880_000
    # Rolling back to 880k means invalidating the block at 880_001.
    assert db._db.invalidate_calls == [child_880001]


@pytest.mark.asyncio
async def test_dumptxoutset_rollback_auto_no_eligible_assumeutxo(tmp_path) -> None:
    """If the tip is below every published assumeutxo height,
    ``type='rollback'`` must raise rather than picking nothing."""
    db = _make_db_with_chain(tip_height=10)  # <<< below mainnet 840k
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "u.dat"

    with pytest.raises(Exception) as excinfo:
        await rpc.rpc_dumptxoutset(str(out_path), type="rollback")
    assert "assumeutxo" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Cleanup: even on dump failure, reconsider_block still runs.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_reconsiders_on_dump_failure(tmp_path, monkeypatch) -> None:
    """Mirror Core's TemporaryRollback dtor invariant: if anything
    between invalidate and the natural end of the call throws, the
    chain still gets the reconsider_block call."""
    db = _make_db_with_chain(tip_height=5)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "boom.dat"
    expected_child_hash = db.chain[3 + 1]

    # Sabotage SnapshotManager.dump_snapshot.
    def _kaboom(*a, **kw):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(
        rpc.node.snapshot_manager, "dump_snapshot", _kaboom
    )

    with pytest.raises(Exception):
        await rpc.rpc_dumptxoutset(
            str(out_path), options={"rollback": 3}
        )

    assert db._db.invalidate_calls == [expected_child_hash]
    assert db._db.reconsider_calls == [expected_child_hash]


# ---------------------------------------------------------------------------
# Reactivation: dumptxoutset rollback now leaves chain at original tip.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dumptxoutset_reactivation_restores_original_tip(tmp_path) -> None:
    """After dump completes, the chain is back at the original tip
    (Core ActivateBestChain analog). chain_restored=True."""
    db = _make_db_with_chain(tip_height=8)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    original_tip_height = db.best_height
    original_tip_hash = db.best_hash
    out_path = tmp_path / "reactivate.dat"

    res = await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": 3})

    # Dump captured the rolled-back state.
    assert res["rollback_height"] == 3
    assert res["base_height"] == 3
    # Chain is restored to original tip after reactivation.
    assert res["chain_restored"] is True
    assert res["original_tip_height"] == original_tip_height
    assert db.best_height == original_tip_height
    assert db.best_hash == original_tip_hash
    # reactivate_best_chain was called exactly once.
    assert db._db.reactivate_calls == 1


@pytest.mark.asyncio
async def test_dumptxoutset_reactivation_with_independently_invalid_block(
    tmp_path,
) -> None:
    """If a block in [target+1..original_tip] is independently invalid
    (separate from the rollback dance), reactivation must stop at that
    block. chain_restored=False with the height we actually reached."""
    db = _make_db_with_chain(tip_height=8)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "stuck.dat"

    # Simulate: reactivation will fail to reconnect at height 6 (e.g.
    # because that block was independently flagged invalid). Stub
    # captures this via fail_reactivate_at.
    db._db.fail_reactivate_at = 6

    res = await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": 3})

    assert res["rollback_height"] == 3
    # Reactivation walked 4 -> 5 then stopped before 6.
    assert db.best_height == 5
    # chain_restored is False because we didn't reach the original tip 8.
    assert res["chain_restored"] is False
    assert res["original_tip_height"] == 8


@pytest.mark.asyncio
async def test_dumptxoutset_reactivation_noop_when_at_tip(tmp_path) -> None:
    """Rolling back to the current tip is a no-op rollback dance:
    reactivation isn't called because invalidate/reconsider didn't fire."""
    db = _make_db_with_chain(tip_height=5)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "noop.dat"

    res = await rpc.rpc_dumptxoutset(
        str(out_path), options={"rollback": db.best_height}
    )

    assert res["rollback_height"] == db.best_height
    # No rollback dance, so no reactivation either.
    assert db._db.reactivate_calls == 0
    assert db._db.invalidate_calls == []
    assert db._db.reconsider_calls == []
    # chain_restored should still be reported as True (chain never moved).
    assert res["chain_restored"] is True


@pytest.mark.asyncio
async def test_dumptxoutset_reactivation_fires_after_reconsider(
    tmp_path,
) -> None:
    """The order is invariant: reconsider_block must precede
    reactivate_best_chain. We assert this by capturing call timestamps
    via list ordering on the stub."""
    db = _make_db_with_chain(tip_height=6)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "order.dat"

    # Hook reactivate_best_chain to assert it sees a non-empty
    # reconsider_calls history when invoked.
    real_reactivate = db._db.reactivate_best_chain

    def wrapped() -> int:
        # By the time we're called, reconsider_block must already have run.
        assert len(db._db.reconsider_calls) >= 1
        return real_reactivate()
    db._db.reactivate_best_chain = wrapped

    res = await rpc.rpc_dumptxoutset(str(out_path), options={"rollback": 2})

    assert res["chain_restored"] is True
    assert db.best_height == 6


@pytest.mark.asyncio
async def test_dumptxoutset_reactivation_explicit_hash_path(tmp_path) -> None:
    """Reactivation also restores chain when rollback was specified by
    display-order hash (not height)."""
    db = _make_db_with_chain(tip_height=7)
    rpc = _make_rpc(db, tmp_path=tmp_path)
    out_path = tmp_path / "byhash-restore.dat"

    target_height = 4
    target_hash_internal = db.chain[target_height]
    target_hash_display = target_hash_internal[::-1].hex()
    original_tip = db.best_height

    res = await rpc.rpc_dumptxoutset(
        str(out_path), options={"rollback": target_hash_display}
    )

    assert res["rollback_height"] == target_height
    # Reactivation put us back at the original tip.
    assert res["chain_restored"] is True
    assert db.best_height == original_tip
    assert db._db.reactivate_calls == 1
