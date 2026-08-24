"""W93 Bug C (intra-block undo loss) — regression test for the *batch*
connect path, ``PyBlockchainDB::connect_blocks_atomic``.

THE BUG
-------
``connect_blocks_atomic`` (``ferrous-utils/sync/src/lib.rs``) used to process
each block in three separate passes:

  1. collect every non-coinbase input and resolve it (overlay -> on-disk),
     tolerating misses;
  2. queue *all* ``batch.delete_cf(chainstate, key)`` calls, writing a
     ``SPENT_CF`` undo record only ``if let Some(utxo_bytes)``;
  3. queue *all* ``batch.put_cf(chainstate, key, ...)`` calls for this
     block's outputs.

Its overlay (``in_batch_added``) held outputs from EARLIER BLOCKS IN THE
BATCH ONLY.  Bitcoin permits a transaction to spend an output created by an
earlier transaction in the SAME block (an "intra-block chain"; the only
ordering rule is creator-before-spender, see Bitcoin Core
``validation.cpp`` ``Chainstate::ConnectBlock`` / ``UpdateCoins``).  For one
of those:

  * phase 1 resolved the prevout to ``None`` — the creating tx's output was
    neither on disk nor yet in the overlay — and a miss was TOLERATED;
  * phase 2 queued the ``delete_cf`` unconditionally but wrote NO undo
    record (the ``Some(...)`` arm never fired);
  * phase 3 queued a ``put_cf`` for that SAME key.

A RocksDB ``WriteBatch`` applies IN ORDER, so delete-then-put left the SPENT
COIN PRESENT in the chainstate and spendable again — and because the miss was
tolerated rather than fatal, the corrupted UTXO set was committed SILENTLY.

Two observable consequences, asserted here:

  (A) the intra-block-created-and-spent coin is PRESENT in the chainstate
      when it must be ABSENT;
  (B) the ``SPENT_CF`` undo record for that outpoint is MISSING when it
      must EXIST (so a later reorg cannot restore the coin).

The safe sibling ``connect_block_from_bytes`` (``lib.rs``, comment "W93 BUG
FIX (Bug C — intra-block undo loss)") already interleaves per transaction and
is used here as the differential oracle: it connects the *identical* block
and must land the *identical* state.

REACHABILITY
------------
``connect_blocks_atomic`` is called from ``src/ouroboros/rpc.py``
``_reorg_to_side_branch_tip``, gated on ``len(chain_to_connect) > 1`` — i.e.
a multi-block side branch.  These tests call it directly (the tighter unit)
over a 2-block batch whose second block is ``[coinbase, txA, txB]`` with
``txB`` spending ``txA:0``.

NOTE ON CRITERION (B)
---------------------
There is no Python binding that reads ``SPENT_CF`` in isolation:
``get_utxo_or_spent`` consults the live chainstate FIRST and only falls back
to ``SPENT_CF``.  On the buggy build the retained chainstate row therefore
MASKS the missing undo record, and (B) can only be asserted jointly with
(A): "gone from the live set AND still recoverable from the undo store".
Post-fix that pair is a positive proof of the undo record (``get_utxo`` is
``None``, so the ``get_utxo_or_spent`` hit can only have come from
``SPENT_CF``).  ``test_control_spend_of_preexisting_ondisk_coin`` proves the
probe itself works on BOTH builds.

Blocks here are built by hand and are NOT coinbase-only — the coinbase-only
shape of ``tests/test_reorg_atomic_connect_pattern_d.py`` (``merkle_root =
coinbase_txid  # single-tx block``) is precisely the blindness that let this
bug survive.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import struct
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Real-extension loader.
#
# tests/conftest.py installs a pure-Python stub under ``sys.modules["sync"]``
# so the Python tree imports without the native library.  We bypass it by
# loading the compiled module straight off disk.  ``OUROBOROS_SYNC_SO``
# overrides the search (used to point at a freshly built .so without
# disturbing the installed one).
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _candidate_so_paths() -> list[Path]:
    override = os.environ.get("OUROBOROS_SYNC_SO")
    if override:
        return [Path(override)]
    out: list[Path] = []
    out.extend(sorted((_REPO_ROOT / ".venv").glob(
        "lib/python*/site-packages/sync/sync*.so")))
    for site in sys.path:
        cand = Path(site) / "sync"
        if cand.is_dir():
            out.extend(sorted(cand.glob("sync*.so")))
    return out


def _load_real_sync():
    """Return the compiled ``sync`` extension, or ``None``."""
    cached = sys.modules.get("_sync_real_intrablock")
    if cached is not None:
        return cached
    for so in _candidate_so_paths():
        if not so.is_file():
            continue
        saved = sys.modules.pop("sync", None)
        try:
            spec = importlib.util.spec_from_file_location("sync", str(so))
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception:  # pragma: no cover - environment dependent
            continue
        finally:
            if saved is not None:
                sys.modules["sync"] = saved
        if hasattr(mod, "PyBlockchainDB") and hasattr(
            mod.PyBlockchainDB, "connect_blocks_atomic"
        ):
            sys.modules["_sync_real_intrablock"] = mod
            return mod
    return None


def _require_sync():
    mod = _load_real_sync()
    if mod is None:
        pytest.skip(
            "compiled `sync` extension with connect_blocks_atomic not found "
            "(set OUROBOROS_SYNC_SO=/path/to/libsync.so)"
        )
    return mod


# ---------------------------------------------------------------------------
# Raw block/transaction builders (regtest, OP_TRUE outputs, legacy encoding).
#
# All 32-byte ids are in *internal* byte order throughout, which is what the
# PyO3 surface takes and returns (``Txid::as_byte_array``).
# ---------------------------------------------------------------------------
REGTEST_BITS = 0x207FFFFF
OP_TRUE = b"\x51"
COIN = 100_000_000


def _dsha(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _ser_script(script: bytes) -> bytes:
    return _varint(len(script)) + script


def _ser_tx(inputs, outputs, version: int = 1, locktime: int = 0) -> bytes:
    """Legacy (non-witness) transaction serialization.

    ``inputs``  — list of ``(prev_txid_bytes, vout, script_sig, sequence)``
    ``outputs`` — list of ``(value_sats, script_pubkey)``
    """
    blob = struct.pack("<I", version) + _varint(len(inputs))
    for prev_txid, vout, script_sig, sequence in inputs:
        blob += (
            prev_txid
            + struct.pack("<I", vout)
            + _ser_script(script_sig)
            + struct.pack("<I", sequence)
        )
    blob += _varint(len(outputs))
    for value, spk in outputs:
        blob += struct.pack("<Q", value) + _ser_script(spk)
    return blob + struct.pack("<I", locktime)


def _merkle_root(txids: list[bytes]) -> bytes:
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [_dsha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def _coinbase_tx(height: int, value: int = 50 * COIN, tag: bytes = b"\x01\x00") -> bytes:
    """BIP34-shaped coinbase with a single OP_TRUE output."""
    h_bytes = height.to_bytes((height.bit_length() + 7) // 8 or 1, "little")
    script_sig = bytes([len(h_bytes)]) + h_bytes + tag
    assert 2 <= len(script_sig) <= 100, "coinbase scriptSig must be 2..100 bytes"
    return _ser_tx(
        [(b"\x00" * 32, 0xFFFFFFFF, script_sig, 0xFFFFFFFF)],
        [(value, OP_TRUE)],
    )


def _solve_header(prev_hash: bytes, merkle_root: bytes, timestamp: int):
    """Grind the nonce until the regtest 0x207fffff target is met."""
    for nonce in range(4_000_000):
        header = (
            struct.pack("<i", 1)
            + prev_hash
            + merkle_root
            + struct.pack("<III", timestamp, REGTEST_BITS, nonce)
        )
        block_hash = _dsha(header)
        if block_hash[31] < 0x7F:
            return header, block_hash
    raise RuntimeError("could not solve regtest header")  # pragma: no cover


def _build_block(prev_hash: bytes, timestamp: int, txs: list[bytes]):
    """Assemble a raw block from already-serialized transactions.

    Returns ``(raw_block, block_hash)``.  The merkle root is computed over
    every transaction — unlike the coinbase-only helper in
    ``test_reorg_atomic_connect_pattern_d.py``.
    """
    root = _merkle_root([_dsha(tx) for tx in txs])
    header, block_hash = _solve_header(prev_hash, root, timestamp)
    return header + _varint(len(txs)) + b"".join(txs), block_hash


def _regtest_genesis_bytes() -> bytes:
    prev_block = b"\x00" * 32
    merkle_root = bytes.fromhex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )[::-1]
    coinbase_tx = bytes.fromhex(
        "01000000"
        "01"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff"
        "4d"
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
        "39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
        "ffffffff"
        "01"
        "00f2052a01000000"
        "43"
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
        "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        "00000000"
    )
    header = (
        struct.pack("<i", 1)
        + prev_block
        + merkle_root
        + struct.pack("<III", 1296688602, REGTEST_BITS, 2)
    )
    return header + b"\x01" + coinbase_tx


BASE_TIME = 1296688800


def _chain_with_four_coinbases(sync, datadir: Path):
    """genesis + h1..h4 coinbase-only blocks via the per-block safe path.

    Returns ``(db, tip_hash, {height: coinbase_txid})``.  Each of h1..h4
    leaves one spendable OP_TRUE coin on disk.
    """
    db = sync.PyBlockchainDB(str(datadir))
    db.connect_block_from_bytes(_regtest_genesis_bytes(), 0)
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 0

    coinbase_txids: dict[int, bytes] = {}
    for height in range(1, 5):
        cb = _coinbase_tx(height, tag=b"\x02C" + bytes([height]))
        raw, block_hash = _build_block(tip_hash, BASE_TIME + height * 600, [cb])
        db.connect_block_from_bytes(raw, height, "regtest")
        coinbase_txids[height] = _dsha(cb)
        tip_hash = block_hash

    assert db.get_best_block() == (tip_hash, 4)
    for height in range(1, 5):
        assert db.get_utxo(coinbase_txids[height], 0) is not None
    return db, tip_hash, coinbase_txids


def _intra_block_batch(tip_hash: bytes, coinbase_txids: dict[int, bytes],
                       *, chained: bool):
    """Build the 2-block batch [h5 (coinbase-only), h6 (3 txs)].

    Block h6 is ``[coinbase, txA, txB]``:

      * ``txA`` spends the on-disk coinbase of h1 and creates ``txA:0``
        and ``txA:1``;
      * ``txB`` spends ``txA:0``  (``chained=True``  — the INTRA-BLOCK CHAIN)
        or the on-disk coinbase of h2 (``chained=False`` — the CONTROL).

    The two variants differ in exactly one field: ``txB``'s prevout.

    Returns ``(batch, txa_txid, txb_txid)`` where ``batch`` is the
    ``[(raw, height), ...]`` list ``connect_blocks_atomic`` takes.
    """
    cb5 = _coinbase_tx(5, tag=b"\x02B5")
    raw5, hash5 = _build_block(tip_hash, BASE_TIME + 5 * 600, [cb5])

    cb6 = _coinbase_tx(6, tag=b"\x02B6")
    tx_a = _ser_tx(
        [(coinbase_txids[1], 0, b"", 0xFFFFFFFF)],
        [(25 * COIN, OP_TRUE), (20 * COIN, OP_TRUE)],
    )
    txa_txid = _dsha(tx_a)
    spend_target = txa_txid if chained else coinbase_txids[2]
    tx_b = _ser_tx(
        [(spend_target, 0, b"", 0xFFFFFFFF)],
        [(24 * COIN, OP_TRUE)],
    )
    txb_txid = _dsha(tx_b)

    raw6, _hash6 = _build_block(hash5, BASE_TIME + 6 * 600, [cb6, tx_a, tx_b])
    return [(raw5, 5), (raw6, 6)], txa_txid, txb_txid


# ---------------------------------------------------------------------------
# (A) The intra-block-created-and-spent coin must be gone from the chainstate.
# ---------------------------------------------------------------------------
def test_intrablock_created_coin_is_absent_from_chainstate(tmp_path) -> None:
    """Criterion (A): delete-then-put must not resurrect a spent coin.

    Block h6 = ``[coinbase, txA, txB]`` with ``txB`` spending ``txA:0``.
    After the batch commits, ``txA:0`` has been created and spent inside the
    same block, so it must NOT be in the live UTXO set.

    Pre-fix this fails: the three-pass shape queues ``delete(txA:0)`` (phase
    2) before ``put(txA:0)`` (phase 3), and a WriteBatch applies in order, so
    the spent coin survives and is spendable again.
    """
    sync = _require_sync()
    db, tip_hash, coinbase_txids = _chain_with_four_coinbases(
        sync, tmp_path / "db")
    batch, txa_txid, txb_txid = _intra_block_batch(
        tip_hash, coinbase_txids, chained=True)

    connected = db.connect_blocks_atomic(batch, "regtest")
    assert len(connected) == 2
    assert db.get_best_block()[1] == 6

    # Sanity: the rest of block h6 landed exactly as expected.
    assert db.get_utxo(coinbase_txids[1], 0) is None, (
        "txA's on-disk input (h1 coinbase) should have been spent")
    assert db.get_utxo(txa_txid, 1) is not None, (
        "txA:1 was never spent and must remain in the UTXO set")
    assert db.get_utxo(txb_txid, 0) is not None, (
        "txB:0 must be in the UTXO set")

    # (A) — the load-bearing assertion.
    assert db.get_utxo(txa_txid, 0) is None, (
        "INTRA-BLOCK UNDO LOSS (W93 Bug C): txA:0 was created by txA and "
        "spent by txB in the SAME block, but it is still in the chainstate "
        "and therefore spendable again. connect_blocks_atomic queued "
        "delete_cf(txA:0) in its spend pass BEFORE put_cf(txA:0) in its "
        "output pass; a RocksDB WriteBatch applies in order, so the put won."
    )

    # Independent restatement of the same corruption: exactly 7 coins should
    # be live (h3/h4/h5/h6 coinbases + txA:1 + txB:0 ... and h1/h2 spent or
    # unspent per the scenario). A retained txA:0 makes it 8.
    assert db.utxo_count() == 7, (
        f"UTXO set has {db.utxo_count()} coins, expected 7 — an extra coin "
        f"means the intra-block-spent output was resurrected"
    )


# ---------------------------------------------------------------------------
# (B) The SPENT_CF undo record for the intra-block spend must exist.
# ---------------------------------------------------------------------------
def test_intrablock_spend_writes_spent_cf_undo_record(tmp_path) -> None:
    """Criterion (B): the spend must leave a reorg-restorable undo record.

    ``get_utxo_or_spent`` reads the live chainstate first and only then falls
    back to ``SPENT_CF``.  So the pair

        get_utxo(txA, 0) is None   AND   get_utxo_or_spent(txA, 0) is not None

    can only be satisfied by a real ``SPENT_CF`` record.

    Pre-fix this fails at the first clause: the resurrected chainstate row
    masks the missing undo record (see the module docstring).  The undo
    record really is absent pre-fix — phase 2 wrote it only inside
    ``if let Some(utxo_bytes)``, and phase 1 resolved the intra-block prevout
    to ``None``.  ``test_control_spend_of_preexisting_ondisk_coin`` shows the
    probe used here does detect undo records on the unpatched build.
    """
    sync = _require_sync()
    db, tip_hash, coinbase_txids = _chain_with_four_coinbases(
        sync, tmp_path / "db")
    batch, txa_txid, _txb_txid = _intra_block_batch(
        tip_hash, coinbase_txids, chained=True)

    db.connect_blocks_atomic(batch, "regtest")

    assert db.get_utxo(txa_txid, 0) is None, (
        "txA:0 is still live, which masks the SPENT_CF probe — see criterion "
        "(A); the undo record is missing too"
    )
    assert db.get_utxo_or_spent(txa_txid, 0) is not None, (
        "no SPENT_CF undo record for txA:0: the intra-block spend cannot be "
        "rolled back, so a later reorg would silently drop the coin"
    )


# ---------------------------------------------------------------------------
# CONTROL — identical scenario, txB spends a PRE-EXISTING on-disk coin.
# Must pass on BOTH the patched and the unpatched build.
# ---------------------------------------------------------------------------
def test_control_spend_of_preexisting_ondisk_coin(tmp_path) -> None:
    """CONTROL: no intra-block chain, therefore no corruption either way.

    Block h6 is byte-for-byte the same shape as the failing case except that
    ``txB`` spends the h2 coinbase (already on disk) instead of ``txA:0``.
    Phase 1's ``multi_get_cf`` finds it, phase 2 writes the undo record, and
    the ordering hazard never arises.

    This is what makes the failure attributable to the INTRA-BLOCK CHAIN
    rather than to the block builder, the merkle root, the multi-tx block
    shape, or the ``get_utxo_or_spent`` probe: change one prevout and the
    same code path is clean.
    """
    sync = _require_sync()
    db, tip_hash, coinbase_txids = _chain_with_four_coinbases(
        sync, tmp_path / "db")
    batch, txa_txid, txb_txid = _intra_block_batch(
        tip_hash, coinbase_txids, chained=False)

    db.connect_blocks_atomic(batch, "regtest")
    assert db.get_best_block()[1] == 6

    # Both spent inputs were on disk: gone from the live set, recoverable
    # from SPENT_CF. This proves the criterion-(B) probe works here.
    for height in (1, 2):
        txid = coinbase_txids[height]
        assert db.get_utxo(txid, 0) is None, (
            f"h{height} coinbase output should have been spent")
        assert db.get_utxo_or_spent(txid, 0) is not None, (
            f"h{height} coinbase output has no SPENT_CF undo record")

    # txA:0 is NOT spent in this variant, so here it MUST still be live.
    assert db.get_utxo(txa_txid, 0) is not None
    assert db.get_utxo(txa_txid, 1) is not None
    assert db.get_utxo(txb_txid, 0) is not None
    assert db.utxo_count() == 7


# ---------------------------------------------------------------------------
# Differential oracle: the batch path must match the already-fixed per-block
# path on the identical blocks.
# ---------------------------------------------------------------------------
def test_batch_path_matches_safe_per_block_path(tmp_path) -> None:
    """``connect_blocks_atomic`` must land what ``connect_block_from_bytes``
    lands for the same blocks.

    ``connect_block_from_bytes`` already carries the W93 Bug C interleave, so
    it is the in-repo oracle for correct intra-block handling.  Pre-fix the
    two paths disagree on ``txA:0`` (and on ``utxo_count``), which is the
    consensus-relevant symptom: which function connected the block decides
    whether the UTXO set is corrupt.
    """
    sync = _require_sync()

    db_batch, tip_hash, coinbase_txids = _chain_with_four_coinbases(
        sync, tmp_path / "db_batch")
    batch, txa_txid, txb_txid = _intra_block_batch(
        tip_hash, coinbase_txids, chained=True)
    db_batch.connect_blocks_atomic(batch, "regtest")

    db_seq, tip_hash_seq, coinbase_txids_seq = _chain_with_four_coinbases(
        sync, tmp_path / "db_seq")
    assert tip_hash_seq == tip_hash and coinbase_txids_seq == coinbase_txids
    for raw, height in batch:
        db_seq.connect_block_from_bytes(raw, height, "regtest")

    assert db_batch.get_best_block() == db_seq.get_best_block()

    probes = [
        ("h1 coinbase", coinbase_txids[1], 0),
        ("h2 coinbase", coinbase_txids[2], 0),
        ("txA:0 (intra-block chain)", txa_txid, 0),
        ("txA:1", txa_txid, 1),
        ("txB:0", txb_txid, 0),
    ]
    mismatches = []
    for label, txid, vout in probes:
        live = (db_batch.get_utxo(txid, vout) is not None,
                db_seq.get_utxo(txid, vout) is not None)
        spent = (db_batch.get_utxo_or_spent(txid, vout) is not None,
                 db_seq.get_utxo_or_spent(txid, vout) is not None)
        if live[0] != live[1] or spent[0] != spent[1]:
            mismatches.append(
                f"{label}: batch live={live[0]} or_spent={spent[0]} | "
                f"per-block live={live[1]} or_spent={spent[1]}")
    assert not mismatches, (
        "connect_blocks_atomic diverges from connect_block_from_bytes: "
        + "; ".join(mismatches)
    )
    assert db_batch.utxo_count() == db_seq.utxo_count(), (
        f"utxo_count differs: batch={db_batch.utxo_count()} "
        f"per-block={db_seq.utxo_count()}"
    )
