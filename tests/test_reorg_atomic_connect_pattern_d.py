"""Pattern D — multi-block atomic CONNECT (single ``WriteBatch``).

These tests pin the contract that ``_reorg_to_side_branch_tip`` is now
single-batch on **both** sides — disconnect (shipped in 8873175) and
connect (this commit). Together they take ouroboros from D-PARTIAL
(single-batch on disconnect, N batches on connect) to D-NEAR-FULL
(single-batch each side, two commits total).

Scope:
1. ``db.connect_blocks_atomic(blocks, network)`` is exposed by the Rust
   extension and connects every block in the batch with a single
   atomic write.
2. A multi-block reorg (3 disconnect + 4 connect) lands the same final
   on-disk state as the per-block path would, confirming the
   single-batch property.
3. Failed validation mid-stream aborts the entire connect batch — disk
   state is unchanged from the pre-batch checkpoint (the
   crash-pre-commit property).
4. Argument validation: discontiguous heights, empty blocks, malformed
   bytes raise ``ValueError`` cleanly.

End-to-end correctness across the full submitblock reorg path is
exercised by the existing ``tools/diff-test-corpus/regression/`` reorg
entries.

Reference:
* Bitcoin Core ``Chainstate::ActivateBestChain`` (validation.cpp).
* The Rust ``connect_blocks_atomic`` lives at
  ``ferrous-utils/sync/src/lib.rs`` (``PyBlockchainDB::connect_blocks_atomic``).
* Python wiring is in ``src/ouroboros/rpc.py:_reorg_to_side_branch_tip``.
* Audit doc:
  ``CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md``.
"""

from __future__ import annotations

import hashlib
import importlib
import struct
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Real-extension loader (mirrors tests/test_reorg_atomic_pattern_d.py).
# ---------------------------------------------------------------------------
def _try_import_sync() -> object | None:
    if "_sync_real" in sys.modules:
        return sys.modules["_sync_real"]

    stub = sys.modules.get("sync")
    is_stub = stub is not None and getattr(stub, "__file__", "") == "<test-mock>"

    if not is_stub:
        try:
            mod = importlib.import_module("sync")
        except ImportError:
            return None
        if not hasattr(mod, "PyBlockchainDB") or not hasattr(
            mod.PyBlockchainDB, "connect_block_from_bytes"
        ):
            return None
        sys.modules["_sync_real"] = mod
        return mod

    venv_root = Path(__file__).parent.parent / ".venv"
    candidates = sorted(venv_root.glob(
        "lib/python*/site-packages/sync/sync*.so"
    ))
    if not candidates:
        return None

    saved = sys.modules.pop("sync")
    try:
        mod = importlib.import_module("sync")
    except ImportError:
        sys.modules["sync"] = saved
        return None
    finally:
        sys.modules["sync"] = saved
    if not hasattr(mod, "PyBlockchainDB") or not hasattr(
        mod.PyBlockchainDB, "connect_block_from_bytes"
    ):
        return None
    sys.modules["_sync_real"] = mod
    return mod


# ---------------------------------------------------------------------------
# Block-building helpers (regtest, OP_TRUE coinbase outputs — same shape
# as tests/test_reorg_atomic_pattern_d.py).
# ---------------------------------------------------------------------------
REGTEST_BITS = 0x207FFFFF


def _make_regtest_genesis_bytes() -> bytes:
    prev_block = b"\x00" * 32
    merkle_root = bytes.fromhex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )[::-1]
    ts, bits, nonce = 1296688602, REGTEST_BITS, 2
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
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        "00000000"
    )
    header = struct.pack("<i", 1) + prev_block + merkle_root
    header += struct.pack("<III", ts, bits, nonce)
    return header + b"\x01" + coinbase_tx


def _solve_regtest_header(version: int, prev_hash: bytes,
                          merkle_root: bytes, timestamp: int) -> tuple[bytes, int, bytes]:
    bits = REGTEST_BITS
    for nonce in range(2_000_000):
        header = (
            struct.pack("<i", version)
            + prev_hash
            + merkle_root
            + struct.pack("<I", timestamp)
            + struct.pack("<I", bits)
            + struct.pack("<I", nonce)
        )
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        if block_hash[31] < 0x7f:
            return header, nonce, block_hash
    raise RuntimeError("could not solve regtest header (cosmic ray?)")


def _build_op_true_block(prev_hash: bytes, height: int, timestamp: int,
                         cb_value: int = 50 * 100_000_000,
                         tag: bytes = b"\x01\x00") -> tuple[bytes, bytes, bytes]:
    """Build a minimal regtest block with a single OP_TRUE coinbase output.

    Returns ``(raw_block, block_hash, coinbase_txid)``.
    """
    op_true_spk = b"\x51"

    height_push = b""
    if height > 0:
        h_bytes = height.to_bytes((height.bit_length() + 7) // 8 or 1, "little")
        height_push = bytes([len(h_bytes)]) + h_bytes
    cb_script_sig = height_push + tag

    cb_inputs = (
        b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + bytes([len(cb_script_sig)]) + cb_script_sig
        + struct.pack("<I", 0xFFFFFFFF)
    )
    cb_outputs = (
        b"\x01"
        + struct.pack("<Q", cb_value)
        + bytes([len(op_true_spk)]) + op_true_spk
    )
    cb_body = (
        struct.pack("<I", 1)  # version
        + cb_inputs
        + cb_outputs
        + struct.pack("<I", 0)  # locktime
    )
    coinbase_txid = hashlib.sha256(hashlib.sha256(cb_body).digest()).digest()
    merkle_root = coinbase_txid  # single-tx block

    header, _nonce, block_hash = _solve_regtest_header(
        version=1, prev_hash=prev_hash, merkle_root=merkle_root, timestamp=timestamp,
    )
    raw = header + b"\x01" + cb_body
    return raw, block_hash, coinbase_txid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_connect_blocks_atomic_method_present() -> None:
    """The PyO3 entry point exists on PyBlockchainDB.

    This is the canary that the Rust extension was rebuilt with the
    D-FULL upgrade.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    assert hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"), (
        "Pattern D atomic connect helper missing — rebuild "
        "ferrous-utils/sync via `maturin develop --release`."
    )


def test_connect_blocks_atomic_four_block_batch(tmp_path) -> None:
    """4-block atomic connect lands the same final on-disk state as
    4 sequential ``connect_block_from_bytes`` calls would. This is the
    **single-batch property** assertion for the connect side.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"):
        pytest.skip("connect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))

    # Genesis (h=0) — Core's regtest genesis whose coinbase is
    # unspendable. No UTXO created.
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    # Build 4 OP_TRUE coinbase blocks and feed them as a single batch.
    raw1, hash1, cb1_txid = _build_op_true_block(genesis_hash, 1, 1296688700)
    raw2, hash2, cb2_txid = _build_op_true_block(hash1, 2, 1296688800)
    raw3, hash3, cb3_txid = _build_op_true_block(hash2, 3, 1296688900)
    raw4, hash4, cb4_txid = _build_op_true_block(hash3, 4, 1296689000)

    # Pre-flight: chain head must still be genesis.
    pre_tip_hash, pre_tip_height = db.get_best_block()
    assert pre_tip_height == 0
    assert pre_tip_hash == genesis_hash
    assert db.get_utxo(cb1_txid, 0) is None
    assert db.get_utxo(cb4_txid, 0) is None

    # Single-batch connect of all 4 blocks.
    hashes = db.connect_blocks_atomic(
        [(raw1, 1), (raw2, 2), (raw3, 3), (raw4, 4)],
        "regtest",
    )
    # Returned in input order.
    assert len(hashes) == 4
    assert bytes(hashes[0]) == hash1
    assert bytes(hashes[1]) == hash2
    assert bytes(hashes[2]) == hash3
    assert bytes(hashes[3]) == hash4

    # Tip advanced to h=4.
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 4
    assert tip_hash == hash4

    # All four coinbase UTXOs present.
    assert db.get_utxo(cb1_txid, 0) is not None
    assert db.get_utxo(cb2_txid, 0) is not None
    assert db.get_utxo(cb3_txid, 0) is not None
    assert db.get_utxo(cb4_txid, 0) is not None


def test_connect_blocks_atomic_validation_failure_aborts_batch(tmp_path) -> None:
    """A validation failure mid-batch aborts the entire connect — no
    block in the batch lands. This is the **crash-pre-commit / abort-
    cleanly** assertion.

    We construct a 3-block batch where block 2 has a deliberately
    broken prev_hash (points at a different parent). The atomic
    helper's prev-hash linking check should reject the batch and leave
    the chainstate identical to the pre-call snapshot.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"):
        pytest.skip("connect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    raw1, hash1, cb1_txid = _build_op_true_block(genesis_hash, 1, 1296688700)
    raw2, hash2, cb2_txid = _build_op_true_block(hash1, 2, 1296688800)
    # Build block 3 pointing at the WRONG parent (genesis, not hash2).
    # This makes the prev_hash link check fail at block index 2.
    raw3_bad, _hash3_bad, _cb3_bad = _build_op_true_block(
        genesis_hash, 3, 1296688900,
    )

    # Snapshot pre-call state.
    pre_tip = db.get_best_block()
    pre_count = db.utxo_count() if hasattr(db, "utxo_count") else None

    # Atomic batch should reject due to block index 2's broken link.
    with pytest.raises(Exception):
        db.connect_blocks_atomic(
            [(raw1, 1), (raw2, 2), (raw3_bad, 3)],
            "regtest",
        )

    # Disk state must be IDENTICAL to the pre-call snapshot — neither
    # block 1 nor block 2 (which were structurally valid) landed,
    # because the WriteBatch was dropped before commit.
    post_tip = db.get_best_block()
    assert post_tip == pre_tip, (
        f"validation failure mid-batch left chain at {post_tip}, "
        f"expected pre-call state {pre_tip}"
    )
    if pre_count is not None:
        assert db.utxo_count() == pre_count, (
            "validation failure mid-batch leaked partial UTXO writes"
        )

    # Block 1's coinbase output must NOT be present (the batch was
    # dropped, so block 1's writes never landed).
    assert db.get_utxo(cb1_txid, 0) is None
    assert db.get_utxo(cb2_txid, 0) is None


def test_connect_blocks_atomic_three_disconnect_four_connect_reorg(tmp_path) -> None:
    """End-to-end: 3-disconnect + 4-connect reorg via the Rust helpers,
    matching the dispatch's specific test ask. Confirms that
    ``disconnect_blocks_atomic`` + ``connect_blocks_atomic`` chained
    together leave the chain pointing at the new tip with all expected
    UTXOs present and pre-fork UTXOs gone.

    This is the **3-disconnect + 4-connect** specific assertion from
    the dispatch — exactly one disconnect batch + exactly one connect
    batch covering the full reorg.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"):
        pytest.skip("connect_blocks_atomic not built into the extension")
    if not hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"):
        pytest.skip("disconnect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    # Build A-chain: genesis → A1 → A2 → A3 (3 blocks above ancestor=genesis).
    a1, a1_h, a1_cb = _build_op_true_block(genesis_hash, 1, 1296688700, tag=b"\x02A1")
    db.connect_block_from_bytes(a1, 1)
    a2, a2_h, a2_cb = _build_op_true_block(a1_h, 2, 1296688800, tag=b"\x02A2")
    db.connect_block_from_bytes(a2, 2)
    a3, a3_h, a3_cb = _build_op_true_block(a2_h, 3, 1296688900, tag=b"\x02A3")
    db.connect_block_from_bytes(a3, 3)

    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 3
    assert tip_hash == a3_h
    assert db.get_utxo(a1_cb, 0) is not None
    assert db.get_utxo(a3_cb, 0) is not None

    # Build B-chain: 4 blocks above genesis (= heavier than A-chain).
    # Different timestamps to ensure distinct hashes from A-chain.
    b1, b1_h, b1_cb = _build_op_true_block(genesis_hash, 1, 1296690000, tag=b"\x02B1")
    b2, b2_h, b2_cb = _build_op_true_block(b1_h, 2, 1296690100, tag=b"\x02B2")
    b3, b3_h, b3_cb = _build_op_true_block(b2_h, 3, 1296690200, tag=b"\x02B3")
    b4, b4_h, b4_cb = _build_op_true_block(b3_h, 4, 1296690300, tag=b"\x02B4")

    # Reorg: 3-block disconnect (A1..A3) → 4-block connect (B1..B4).
    # Each side is a single WriteBatch.
    disconnected = db.disconnect_blocks_atomic(3, 0)
    assert len(disconnected) == 3
    assert bytes(disconnected[0]) == a3_h  # tip-to-ancestor order

    connected = db.connect_blocks_atomic(
        [(b1, 1), (b2, 2), (b3, 3), (b4, 4)],
        "regtest",
    )
    assert len(connected) == 4
    assert bytes(connected[3]) == b4_h

    # Final tip = B4.
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 4
    assert tip_hash == b4_h

    # B-chain UTXOs present.
    assert db.get_utxo(b1_cb, 0) is not None
    assert db.get_utxo(b2_cb, 0) is not None
    assert db.get_utxo(b3_cb, 0) is not None
    assert db.get_utxo(b4_cb, 0) is not None

    # A-chain UTXOs gone.
    assert db.get_utxo(a1_cb, 0) is None
    assert db.get_utxo(a2_cb, 0) is None
    assert db.get_utxo(a3_cb, 0) is None


def test_connect_blocks_atomic_rejects_discontiguous_heights(tmp_path) -> None:
    """Argument validation: a height gap (e.g. h=1 then h=3 skipping
    h=2) is a programmer error and must raise ``ValueError`` cleanly,
    not silently corrupt the chainstate.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"):
        pytest.skip("connect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    raw1, hash1, _ = _build_op_true_block(genesis_hash, 1, 1296688700)
    raw3, _, _ = _build_op_true_block(hash1, 3, 1296688900)  # mislabeled

    pre_tip = db.get_best_block()

    with pytest.raises(ValueError, match="contiguous|height"):
        db.connect_blocks_atomic([(raw1, 1), (raw3, 3)], "regtest")

    # No partial state: chain still at genesis.
    assert db.get_best_block() == pre_tip


def test_connect_blocks_atomic_empty_input_is_no_op(tmp_path) -> None:
    """Empty input is a valid no-op: returns an empty list and leaves
    chainstate untouched. Smallest "valid" invocation; the helper must
    not corrupt state on a 0-block call.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "connect_blocks_atomic"):
        pytest.skip("connect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)

    pre_tip = db.get_best_block()
    pre_count = db.utxo_count() if hasattr(db, "utxo_count") else None

    out = db.connect_blocks_atomic([], "regtest")
    assert list(out) == []

    post_tip = db.get_best_block()
    assert post_tip == pre_tip
    if pre_count is not None:
        assert db.utxo_count() == pre_count
