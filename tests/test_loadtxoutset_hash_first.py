"""loadtxoutset must verify the snapshot before it touches the chainstate.

Security audit H7 (audits/security/ouroboros-2026-10-30.md): load_snapshot
called snapshot_load_begin, which clears CHAINSTATE_CF, then streamed the
coins in, and only then compared HASH_SERIALIZED. A snapshot with the wrong
hash, or one cut short mid-coins, therefore failed AFTER the live UTXO set
had been replaced by the snapshot's coins. A snapshot with no assumeUTXO
entry was loaded on regtest at height 0 with no hash check at all.

Core populates a separate chainstate and checks the hash before it is used;
on failure only that chainstate is deleted (validation.cpp:5677-5698,
5912-5914), and it refuses any snapshot whose height has no assumeUTXO
entry (validation.cpp:5775-5780).

Every test here runs the real Rust extension on a scratch regtest datadir
with blocks 1..5 and checks the state that gettxoutsetinfo, getblockcount
and the in-progress marker report, before and after the refused load.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import COIN, OP_TRUE, Chain, dsha  # noqa: E402

TIP = 5  # snapshot base height
NODE_TIP = TIP + 2  # the node under test is ahead of the snapshot base
P2PKH = b"\x76\xa9\x14" + b"\x5a" * 20 + b"\x88\xac"


@pytest.fixture(autouse=True)
def _use_real_sync():
    from ouroboros.snapshot import clear_regtest_assumeutxo

    with real_sync_installed(sync):
        yield
    clear_regtest_assumeutxo()


def _node(tmp_path, name: str, tip: int = NODE_TIP):
    """A regtest datadir with blocks 1..tip and a few non-coinbase coins.

    The coins cover a raw script (OP_TRUE) and a special-cased compressed
    script (P2PKH), so both script encodings are read back by the loader.
    """
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer
    from ouroboros.snapshot import SnapshotManager

    datadir = str(tmp_path / name)
    bdb = BlockchainDatabase(datadir)
    chain = Chain(bdb._db, tip=tip, n_fund=2)
    bdb._db.add_utxo_raw(dsha(b"hash-first-p2pkh"), 3, 7 * COIN, P2PKH, 2, False)
    sm = SnapshotManager(bdb, "regtest", datadir)
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = SimpleNamespace(
        network="regtest", db=bdb, snapshot_manager=sm, mempool=[], validator=None,
    )
    rpc._current_wallet_name = None
    rpc.block_submission_paused = False
    return SimpleNamespace(bdb=bdb, chain=chain, sm=sm, rpc=rpc)


def _state(node) -> dict:
    """What an operator sees: gettxoutsetinfo, the tip, the marker."""
    info = asyncio.run(node.rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_3"))
    tip_hash, tip_height = node.bdb._db.get_best_block()
    return {
        "txouts": info["txouts"],
        "total_amount": info["total_amount"].text,
        "hash_serialized_3": info["hash_serialized_3"],
        "height": info["height"],
        "bestblock": info["bestblock"],
        "tip": (bytes(tip_hash), tip_height),
        "marker": node.bdb._db.has_snapshot_load_marker(),
    }


def _dump(node, path) -> dict:
    """dumptxoutset of the node's own tip; returns the dump's stats."""
    return node.sm.dump_snapshot_with_stats(str(path))


def _register(base_hash: bytes, hash_serialized: bytes, chain_tx_count: int = TIP + 1):
    from ouroboros.snapshot import AssumeutxoData, register_regtest_assumeutxo

    register_regtest_assumeutxo(AssumeutxoData(
        height=TIP,
        block_hash=base_hash,
        hash_serialized=hash_serialized,
        chain_tx_count=chain_tx_count,
    ))


def _snapshot_from_other_chain(tmp_path):
    """A snapshot at block TIP of the same chain, plus the node it came from.

    The node under test has blocks up to NODE_TIP, so the base block is in
    its headers chain; the snapshot's coin set (one extra coin, no
    coinbases above TIP) is honest and self-consistent but is not the node's
    UTXO set, and its base is not the node's tip.
    """
    other = _node(tmp_path, "other", tip=TIP)
    other.bdb._db.add_utxo_raw(dsha(b"other-chain-extra"), 0, 3 * COIN, OP_TRUE, 4, False)
    snap = tmp_path / "other.dat"
    stats = _dump(other, snap)
    return other, snap, stats


def _assert_refused_untouched(target, before: dict) -> None:
    after = _state(target)
    assert after == before, f"refused load changed the node: {before} -> {after}"


def test_loadtxoutset_hash_mismatch_leaves_chainstate_and_tip(tmp_path):
    """The commitment does not match the file: refuse, change nothing."""
    target = _node(tmp_path, "target")
    _other, snap, stats = _snapshot_from_other_chain(tmp_path)
    wrong = bytes(b ^ 0xFF for b in stats["hash_serialized"])
    _register(stats["base_hash"], wrong)
    before = _state(target)
    assert before["txouts"] == NODE_TIP + 3 and before["tip"][1] == NODE_TIP

    with pytest.raises(ValueError, match="Bad snapshot content hash"):
        target.sm.load_snapshot(str(snap))

    _assert_refused_untouched(target, before)
    assert target.sm.snapshot_loaded is False


def test_loadtxoutset_rpc_hash_mismatch_leaves_gettxoutsetinfo_and_tip(tmp_path):
    """The same refusal through the loadtxoutset RPC, as an operator runs it."""
    from fastapi import HTTPException

    target = _node(tmp_path, "target")
    _other, snap, stats = _snapshot_from_other_chain(tmp_path)
    assert target.bdb.has_block_hash(stats["base_hash"])
    _register(stats["base_hash"], bytes(b ^ 0xFF for b in stats["hash_serialized"]))
    before = _state(target)
    count_before = asyncio.run(target.rpc.rpc_getblockcount())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(target.rpc.rpc_loadtxoutset(str(snap)))
    assert "Bad snapshot content hash" in str(exc.value.detail)

    _assert_refused_untouched(target, before)
    assert asyncio.run(target.rpc.rpc_getblockcount()) == count_before == NODE_TIP


def test_loadtxoutset_truncated_mid_coins_leaves_chainstate_and_tip(tmp_path):
    """A file cut off half way through its coins: refuse, change nothing."""
    target = _node(tmp_path, "target")
    _other, snap, stats = _snapshot_from_other_chain(tmp_path)
    _register(stats["base_hash"], stats["hash_serialized"])
    raw = snap.read_bytes()
    header = 5 + 2 + 4 + 32 + 8
    snap.write_bytes(raw[: header + (len(raw) - header) // 2])
    before = _state(target)

    with pytest.raises((ValueError, EOFError)):
        target.sm.load_snapshot(str(snap))

    _assert_refused_untouched(target, before)


def test_loadtxoutset_truncated_inside_last_script_leaves_chainstate_and_tip(tmp_path):
    """Cut inside the last coin's script: a short read must not parse as a
    shorter script. Refuse before any write."""
    target = _node(tmp_path, "target")
    _other, snap, stats = _snapshot_from_other_chain(tmp_path)
    _register(stats["base_hash"], stats["hash_serialized"])
    raw = snap.read_bytes()
    snap.write_bytes(raw[:-1])
    before = _state(target)

    with pytest.raises(EOFError, match="script"):
        target.sm.load_snapshot(str(snap))

    _assert_refused_untouched(target, before)


def test_loadtxoutset_without_assumeutxo_entry_is_refused(tmp_path):
    """No known commitment for the base block: refuse (Core does, on regtest
    too) instead of loading it unchecked at height 0."""
    target = _node(tmp_path, "target")
    _other, snap, _stats = _snapshot_from_other_chain(tmp_path)
    before = _state(target)

    with pytest.raises(ValueError, match="not recognized"):
        target.sm.load_snapshot(str(snap))

    _assert_refused_untouched(target, before)


def test_loadtxoutset_valid_snapshot_still_loads(tmp_path):
    """Control: a snapshot that matches its commitment is not refused, and
    the node then reports exactly the snapshot's UTXO set at its base."""
    target = _node(tmp_path, "target")
    other, snap, stats = _snapshot_from_other_chain(tmp_path)
    _register(stats["base_hash"], stats["hash_serialized"])
    expected = _state(other)
    assert _state(target)["hash_serialized_3"] != expected["hash_serialized_3"]

    target.sm.load_snapshot(str(snap))

    after = _state(target)
    assert after["marker"] is False
    assert after["tip"] == (stats["base_hash"], TIP)
    assert after["hash_serialized_3"] == stats["hash_serialized"][::-1].hex()
    for key in ("txouts", "total_amount", "hash_serialized_3", "height", "bestblock"):
        assert after[key] == expected[key], key
    assert target.sm.snapshot_loaded is True


def test_loadtxoutset_file_changed_between_passes_is_not_committed(tmp_path, monkeypatch):
    """The file is read twice. If it changes after the hash pass, the coins
    written are not the coins verified: the load must fail, the tip must not
    move to the snapshot base, and the marker must stay set so the next boot
    discards the partial chainstate."""
    target = _node(tmp_path, "target")
    _other, snap, stats = _snapshot_from_other_chain(tmp_path)
    _register(stats["base_hash"], stats["hash_serialized"])

    real_begin = target.bdb.snapshot_load_begin

    def begin_then_tamper(base_hash, height):
        raw = bytearray(snap.read_bytes())
        _flip_amount_of_last_coin(raw)
        with open(snap, "r+b") as fh:  # same inode: the loader's open fd sees it
            fh.write(bytes(raw))
        real_begin(base_hash, height)

    monkeypatch.setattr(target.bdb, "snapshot_load_begin", begin_then_tamper)

    with pytest.raises(ValueError, match="changed while it was being loaded"):
        target.sm.load_snapshot(str(snap))

    tip_hash, tip_height = target.bdb._db.get_best_block()
    assert bytes(tip_hash) != stats["base_hash"]
    assert target.bdb._db.has_snapshot_load_marker() is True
    assert target.sm.snapshot_loaded is False


def _flip_amount_of_last_coin(raw: bytearray) -> None:
    """Change the last coin's compressed amount without breaking the parse.

    The coins section ends ``... varint(code) varint(amount) varint(nsize)
    script``; every coin these fixtures write has a 1-byte OP_TRUE script
    (nsize 7) last, and amounts whose compressed VARINT ends in one byte
    below 0x80. Bump that byte so the file still parses but hashes
    differently.
    """
    assert raw[-1] == 0x51 and raw[-2] == 0x07, raw[-8:].hex()
    assert raw[-3] < 0x7F
    raw[-3] += 1
