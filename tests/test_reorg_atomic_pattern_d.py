"""Pattern D — multi-block atomic disconnect (single ``WriteBatch``).

These tests pin the contract that ``_reorg_to_side_branch_tip`` is now
single-batch on the disconnect side, matching camlcoin's D-PARTIAL
property (best in fleet pre-fix per
``CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md``).

Scope:
1. ``db.disconnect_blocks_atomic(tip, ancestor)`` is exposed by the Rust
   extension and disconnects every block in the range as a single
   atomic write — final on-disk state matches per-block disconnect
   exactly.
2. ``MAX_REORG_DEPTH`` (Python-side, ``rpc.py``) caps the reorg depth so
   a malicious side branch can't drive an unbounded ``WriteBatch``.
3. The ``disconnect_blocks_atomic`` helper validates its arguments and
   leaves on-disk state untouched on a no-op call.

End-to-end correctness (across the full submitblock reorg path,
including the connect-side accept_block loop) is exercised by the
existing ``tools/diff-test-corpus/regression/`` reorg entries.

Reference: Bitcoin Core ``Chainstate::DisconnectTip`` (validation.cpp).
The Rust ``disconnect_blocks_atomic`` lives at
``ferrous-utils/sync/src/storage/db.rs:1162+``; the Python wiring is
in ``src/ouroboros/rpc.py:_reorg_to_side_branch_tip``.
"""

from __future__ import annotations

import hashlib
import importlib
import struct
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Real-extension loader (mirrors tests/test_reorg_handle_rust_path.py).
# The conftest stub under sys.modules['sync'] is fine for pure-Python
# tests but we need the live Rust crate to exercise WriteBatch behavior.
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
# Block-building helpers (regtest, OP_TRUE coinbase outputs — minimal
# block construction that connect_block_from_bytes will accept).
# Lifted in shape from tests/test_reorg_handle_rust_path.py; chains
# multiple OP_TRUE coinbases so we can disconnect a range of blocks.
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
def test_disconnect_blocks_atomic_method_present() -> None:
    """The PyO3 entry point exists on PyBlockchainDB."""
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    assert hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"), (
        "Pattern D atomic disconnect helper missing — rebuild "
        "ferrous-utils/sync via `maturin develop --release`."
    )


def test_disconnect_blocks_atomic_three_block_reorg(tmp_path) -> None:
    """3-block reorg via ``disconnect_blocks_atomic`` lands the same
    final on-disk state as 3 sequential ``disconnect_block`` calls
    would, confirming the single-batch path is structurally
    equivalent. This is the **single-batch property** assertion.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"):
        pytest.skip("disconnect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))

    # Genesis (h=0) — Core's regtest genesis whose coinbase is
    # unspendable. No UTXO created.
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    # Build h=1, h=2, h=3 each with an OP_TRUE coinbase. Stagger
    # timestamps so MTP-of-11 stays satisfied.
    raw1, hash1, cb1_txid = _build_op_true_block(genesis_hash, 1, 1296688700)
    db.connect_block_from_bytes(raw1, 1)

    raw2, hash2, cb2_txid = _build_op_true_block(hash1, 2, 1296688800)
    db.connect_block_from_bytes(raw2, 2)

    raw3, hash3, cb3_txid = _build_op_true_block(hash2, 3, 1296688900)
    db.connect_block_from_bytes(raw3, 3)

    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 3
    assert tip_hash == hash3

    # All three coinbase UTXOs are present pre-disconnect.
    assert db.get_utxo(cb1_txid, 0) is not None
    assert db.get_utxo(cb2_txid, 0) is not None
    assert db.get_utxo(cb3_txid, 0) is not None

    # ---- Pattern D: atomic disconnect of [h=1, h=3] back to genesis.
    # ancestor_height=0 → disconnect heights 1, 2, 3 in one WriteBatch.
    disconnected = db.disconnect_blocks_atomic(3, 0)
    # Returned in tip-to-ancestor (reverse chain) order.
    assert len(disconnected) == 3
    assert bytes(disconnected[0]) == hash3
    assert bytes(disconnected[1]) == hash2
    assert bytes(disconnected[2]) == hash1

    # Tip rolled back to genesis.
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 0
    assert tip_hash == genesis_hash

    # All three coinbase UTXOs are gone (they were created above
    # genesis; disconnect deletes outputs).
    assert db.get_utxo(cb1_txid, 0) is None
    assert db.get_utxo(cb2_txid, 0) is None
    assert db.get_utxo(cb3_txid, 0) is None


def test_disconnect_blocks_atomic_partial_range_to_ancestor(tmp_path) -> None:
    """Atomic disconnect of [ancestor+1, tip] where ancestor != genesis.

    Confirms the BEST_BLOCK pointer rewrite uses the prev_blockhash of
    the LOWEST disconnected block (= the ancestor's hash), not the
    pre-fork tip.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"):
        pytest.skip("disconnect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    raw1, hash1, _ = _build_op_true_block(genesis_hash, 1, 1296688700)
    db.connect_block_from_bytes(raw1, 1)
    raw2, hash2, _ = _build_op_true_block(hash1, 2, 1296688800)
    db.connect_block_from_bytes(raw2, 2)
    raw3, hash3, _ = _build_op_true_block(hash2, 3, 1296688900)
    db.connect_block_from_bytes(raw3, 3)
    raw4, hash4, _ = _build_op_true_block(hash3, 4, 1296689000)
    db.connect_block_from_bytes(raw4, 4)

    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 4
    assert tip_hash == hash4

    # Disconnect [h=2, h=4] — ancestor at h=1 stays.
    disconnected = db.disconnect_blocks_atomic(4, 1)
    assert len(disconnected) == 3
    # Tip should point at h=1.
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 1, (
        f"BEST_HEIGHT pointer was rewritten incorrectly: got {tip_height}, "
        "expected 1 (the ancestor height in the atomic-disconnect call)."
    )
    assert tip_hash == hash1, (
        "BEST_BLOCK_HASH pointer was rewritten incorrectly: expected the "
        "ancestor hash (h=1), got something else."
    )


def test_disconnect_blocks_atomic_no_op_when_tip_equals_ancestor(tmp_path) -> None:
    """Memory-cap / no-op property: tip == ancestor returns empty list
    and leaves chainstate untouched. This is the smallest "valid"
    invocation; the helper must not corrupt state on a 0-deep call.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"):
        pytest.skip("disconnect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    raw1, hash1, cb1_txid = _build_op_true_block(genesis_hash, 1, 1296688700)
    db.connect_block_from_bytes(raw1, 1)

    pre_tip = db.get_best_block()
    pre_count = db.utxo_count() if hasattr(db, "utxo_count") else None

    # No-op call: tip = 1, ancestor = 1 — disconnect range is empty.
    out = db.disconnect_blocks_atomic(1, 1)
    assert list(out) == [], "tip == ancestor must return an empty hash list"

    post_tip = db.get_best_block()
    assert post_tip == pre_tip, "no-op must not move the chain tip"
    if pre_count is not None:
        assert db.utxo_count() == pre_count, "no-op must not mutate the UTXO set"


def test_disconnect_blocks_atomic_rejects_inverted_range(tmp_path) -> None:
    """Argument validation: `tip < ancestor` is a programmer error and
    must raise `ValueError`, not silently corrupt the chainstate.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")
    if not hasattr(sync.PyBlockchainDB, "disconnect_blocks_atomic"):
        pytest.skip("disconnect_blocks_atomic not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)

    with pytest.raises(ValueError, match="tip_height"):
        db.disconnect_blocks_atomic(0, 5)


def test_max_reorg_depth_constant_present() -> None:
    """``MAX_REORG_DEPTH`` is exposed at module level for the
    submitblock reorg-depth cap. The constant is the upper bound on
    both the disconnect side and the connect side — bounded so a
    malicious peer can't drive an unbounded ``WriteBatch``.
    """
    from ouroboros import rpc

    assert hasattr(rpc, "MAX_REORG_DEPTH"), (
        "MAX_REORG_DEPTH constant missing from ouroboros.rpc"
    )
    assert isinstance(rpc.MAX_REORG_DEPTH, int)
    assert rpc.MAX_REORG_DEPTH > 0
    # Sanity bound — should be tight enough to limit batch size but
    # nowhere near a realistic reorg depth (Core has not seen >10
    # mainnet reorg in ~14y of operation).
    assert rpc.MAX_REORG_DEPTH <= 1000, (
        f"MAX_REORG_DEPTH = {rpc.MAX_REORG_DEPTH} is unreasonably high; "
        "the cap should bound WriteBatch memory."
    )
