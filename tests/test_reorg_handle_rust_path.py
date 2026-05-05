"""
Integration test for the Python -> Rust reorg disconnect path.

Verifies that ``BlockSync._handle_reorg`` no longer drops ``height`` and
``is_coinbase`` when restoring spent UTXOs after a chain reorganization.

Until this fix, the Python implementation rebuilt the spent-UTXO list by
searching backward through the previous 100 blocks and emitted a 4-tuple
``(txid, vout, value, script_pubkey)`` -- losing the per-coin metadata
that drives the BIP-34 / coinbase-maturity rules.  The Rust crate
already had a correct implementation
(``ferrous-utils/sync/src/storage/db.rs::disconnect_block_at_height``)
exposed via PyO3 as ``db.disconnect_block(height)``, but the live
Python caller never invoked it.

This test exercises the new flow against the real Rust ``sync``
extension:

    1. Build a 2-block regtest fork on top of genesis.
    2. Block 1 has one spendable P2WSH coinbase output (creating a UTXO
       with ``height=1, is_coinbase=true``).
    3. Block 2 spends that coinbase output (creating a UTXO with
       ``height=2, is_coinbase=false``).
    4. Call ``db.disconnect_block(2)`` (the path the rewritten
       ``_handle_reorg`` invokes).
    5. Assert that the restored UTXO at the original outpoint has
       ``height=1`` and ``is_coinbase=true`` -- the matured-coinbase
       contract.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Rust-extension loader copied from tests/test_snapshot.py: the conftest
# stub installed under sys.modules['sync'] is fine for pure-Python tests
# but we need the real Rust code to exercise connect/disconnect.
# ---------------------------------------------------------------------------
def _try_import_sync() -> object | None:
    import importlib
    import sys

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
# Block-building helpers (regtest, target = 0x207fffff is permissive enough
# that nonce=0..1M almost always solves).
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
    """Return (header_bytes, nonce, block_hash) for a regtest header."""
    bits = REGTEST_BITS
    for nonce in range(1_500_000):
        header = (
            struct.pack("<i", version)
            + prev_hash
            + merkle_root
            + struct.pack("<I", timestamp)
            + struct.pack("<I", bits)
            + struct.pack("<I", nonce)
        )
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        # regtest target ~ 0x7fffff << 232 LE; require top byte < 0x7f.
        if block_hash[31] < 0x7f:
            return header, nonce, block_hash
    raise RuntimeError("could not solve regtest header (cosmic ray?)")


def _build_block_with_coinbase(
    prev_hash: bytes,
    height: int,
    timestamp: int,
    cb_outputs: list[tuple[int, bytes]],
    extra_txs_with_witness: list[tuple[bytes, list[list[bytes]]]] | None = None,
) -> tuple[bytes, bytes, bytes, int]:
    """Build a regtest block.

    Returns (raw_block_bytes_with_witnesses, block_hash, coinbase_txid,
    coinbase_value_total).  ``cb_outputs`` is a list of
    ``(value_sat, script_pubkey)`` for the coinbase outputs.

    ``extra_txs_with_witness`` is a list of ``(tx_bytes_no_witness,
    witness_stacks)`` for non-coinbase txs.  Witness stacks are encoded
    inline at serialization time.
    """
    # ----- Coinbase tx (no witness; segwit witness commitment magic is
    # NOT inserted because the test block contains no witness data when
    # extra_txs_with_witness is None or has empty stacks).  When witness
    # data is present, we emit a BIP-141 witness commitment output and
    # the coinbase witness nonce.  Reference: bitcoin-core
    # validation.cpp:3870-3901.
    has_witness = bool(extra_txs_with_witness and any(
        any(stack for stack in stacks) for _, stacks in extra_txs_with_witness
    ))

    # BIP34 height push + arbitrary tag
    height_push = b""
    if height > 0:
        h_bytes = height.to_bytes((height.bit_length() + 7) // 8 or 1, "little")
        height_push = bytes([len(h_bytes)]) + h_bytes
    cb_script_sig = height_push + b"\x01\x00"  # arbitrary OP_0 tail

    cb_inputs = (
        b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + bytes([len(cb_script_sig)]) + cb_script_sig
        + struct.pack("<I", 0xFFFFFFFF)
    )

    cb_output_bytes = bytes([len(cb_outputs) + (1 if has_witness else 0)])
    for value, spk in cb_outputs:
        cb_output_bytes += struct.pack("<Q", value) + bytes([len(spk)]) + spk

    if has_witness:
        # Compute witness merkle root (coinbase wtxid = 0); we'll fix
        # commitment after assembling all wtxids below.  Placeholder for
        # now, recomputed in two phases.
        commitment_placeholder = b"\x00" * 32
        commit_spk = bytes([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]) + commitment_placeholder
        cb_output_bytes += struct.pack("<Q", 0) + bytes([len(commit_spk)]) + commit_spk

    # Coinbase no-witness body (used for txid + initial assembly)
    cb_body_no_witness = (
        struct.pack("<I", 1)  # version
        + cb_inputs
        + cb_output_bytes
        + struct.pack("<I", 0)  # locktime
    )
    coinbase_txid = hashlib.sha256(hashlib.sha256(cb_body_no_witness).digest()).digest()

    # ----- Non-coinbase txs
    extra_tx_bodies: list[bytes] = []
    extra_wtxids: list[bytes] = []
    for tx_bytes_no_witness, witness_stacks in (extra_txs_with_witness or []):
        # txid is hash of no-witness body
        txid = hashlib.sha256(hashlib.sha256(tx_bytes_no_witness).digest()).digest()
        # If witness stacks empty, wtxid == txid.
        if any(stack for stack in witness_stacks):
            # Splice witness data in after the input list.  For our test
            # we don't actually need real witness data — we never set
            # has_witness=True — so this path is reserved for future
            # extension.
            raise NotImplementedError("witness extra tx path not used in this test")
        extra_tx_bodies.append(tx_bytes_no_witness)
        extra_wtxids.append(txid)  # no witness → wtxid == txid

    # ----- If we declared has_witness=True we'd recompute the
    # commitment + rebuild the coinbase, but in this test we keep
    # has_witness=False so non-coinbase txs are plain serialized bodies.

    # ----- Merkle root over txids (no-witness)
    txids = [coinbase_txid]
    for body in extra_tx_bodies:
        txids.append(hashlib.sha256(hashlib.sha256(body).digest()).digest())

    def _merkle_root(hashes: list[bytes]) -> bytes:
        if not hashes:
            return b"\x00" * 32
        cur = list(hashes)
        while len(cur) > 1:
            if len(cur) & 1:
                cur.append(cur[-1])
            nxt = []
            for i in range(0, len(cur), 2):
                nxt.append(hashlib.sha256(hashlib.sha256(cur[i] + cur[i+1]).digest()).digest())
            cur = nxt
        return cur[0]

    merkle_root = _merkle_root(txids)

    # ----- Header
    header, _nonce, block_hash = _solve_regtest_header(
        version=1, prev_hash=prev_hash, merkle_root=merkle_root, timestamp=timestamp
    )

    # ----- Tx count varint + tx bodies (no witness in this test path)
    tx_count = 1 + len(extra_tx_bodies)
    if tx_count < 0xfd:
        tx_count_varint = bytes([tx_count])
    else:
        tx_count_varint = b"\xfd" + struct.pack("<H", tx_count)

    block_bytes = header + tx_count_varint + cb_body_no_witness
    for body in extra_tx_bodies:
        block_bytes += body

    cb_total_value = sum(v for v, _ in cb_outputs)
    return block_bytes, block_hash, coinbase_txid, cb_total_value


def _build_spend_tx(
    prev_txid: bytes,
    prev_vout: int,
    out_value: int,
    out_script_pubkey: bytes,
    sequence: int = 0xFFFFFFFF,
) -> bytes:
    """Serialize a 1-in 1-out non-witness transaction with empty scriptSig."""
    return (
        struct.pack("<I", 1)             # version
        + b"\x01"                         # 1 input
        + prev_txid
        + struct.pack("<I", prev_vout)
        + b"\x00"                         # empty scriptSig
        + struct.pack("<I", sequence)
        + b"\x01"                         # 1 output
        + struct.pack("<Q", out_value)
        + bytes([len(out_script_pubkey)]) + out_script_pubkey
        + struct.pack("<I", 0)            # locktime
    )


# ---------------------------------------------------------------------------
# The actual test
# ---------------------------------------------------------------------------
def test_disconnect_block_preserves_height_and_is_coinbase(tmp_path) -> None:
    """db.disconnect_block(h) restores spent UTXOs with full Coin metadata.

    Specifically, after disconnecting a block whose non-coinbase tx
    spent the coinbase output of the previous block, the restored UTXO
    must have:

      * ``is_coinbase = True``
      * ``height = <height of the block whose coinbase created it>``

    Both fields were dropped on the floor by the previous Python
    ``_restore_utxos_from_block`` implementation, which built a 4-tuple
    and never carried metadata.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))

    # ---- Genesis (height 0) — Core's regtest genesis whose coinbase
    # is unspendable per Core (validation.cpp:2337-2343).  No UTXO
    # created.
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, genesis_height = db.get_best_block()
    assert genesis_height == 0
    assert db.utxo_count() == 0

    # ---- Block 1: anyone-can-spend coinbase output we can later
    # consume from a non-coinbase tx.  Use OP_TRUE (0x51) directly as
    # scriptPubKey -- one byte, no witness needed.
    op_true_spk = b"\x51"
    cb1_value = 50 * 100_000_000  # 50 BTC
    block1, block1_hash, cb1_txid, _ = _build_block_with_coinbase(
        prev_hash=genesis_hash,
        height=1,
        timestamp=1296688700,
        cb_outputs=[(cb1_value, op_true_spk)],
    )
    db.connect_block_from_bytes(block1, 1)
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 1
    assert tip_hash == block1_hash

    # The block 1 coinbase output should be in the UTXO set with
    # height=1, is_coinbase=True.
    pre_utxo = db.get_utxo(cb1_txid, 0)
    assert pre_utxo is not None, "block 1 coinbase output missing from UTXO set"
    assert pre_utxo.height == 1
    assert pre_utxo.is_coinbase is True
    assert int(pre_utxo.amount) == cb1_value
    assert bytes(pre_utxo.script_pubkey) == op_true_spk

    # ---- Block 2: coinbase + a non-coinbase tx that spends block 1's
    # coinbase.  The non-coinbase tx pays 49.999 BTC to a fresh
    # OP_RETURN (filtered out -> creates 0 UTXOs).  Choosing OP_RETURN
    # for the spend output keeps utxo_count predictable: block 2
    # coinbase adds 1 UTXO, the spend creates 0, the spend consumes 1.
    spend_value = cb1_value - 100_000  # leave a 0.001 BTC fee
    spend_spk = bytes([0x6a, 0x01, 0x00])  # OP_RETURN <0x00>
    spend_tx = _build_spend_tx(
        prev_txid=cb1_txid,
        prev_vout=0,
        out_value=spend_value,
        out_script_pubkey=spend_spk,
    )
    cb2_value = 50 * 100_000_000
    block2, block2_hash, cb2_txid, _ = _build_block_with_coinbase(
        prev_hash=block1_hash,
        height=2,
        timestamp=1296688800,
        cb_outputs=[(cb2_value, op_true_spk)],
        extra_txs_with_witness=[(spend_tx, [[]])],
    )
    db.connect_block_from_bytes(block2, 2)
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 2
    assert tip_hash == block2_hash

    # Block 1's coinbase output should now be spent.
    assert db.get_utxo(cb1_txid, 0) is None

    # ---- Disconnect block 2 — this is what the rewritten
    # _handle_reorg invokes via asyncio.to_thread.
    disconnected = db.disconnect_block(2)
    assert bytes(disconnected) == block2_hash

    # Tip rolls back to block 1.
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 1
    assert tip_hash == block1_hash

    # Block 2 coinbase output is gone.
    assert db.get_utxo(cb2_txid, 0) is None

    # *** The bug under test ***
    # Block 1's coinbase output must be back in the UTXO set with the
    # ORIGINAL height + is_coinbase fields, not zeroed/false.
    restored = db.get_utxo(cb1_txid, 0)
    assert restored is not None, (
        "block 1 coinbase output not restored — disconnect dropped it"
    )
    assert restored.height == 1, (
        f"restored UTXO has wrong height {restored.height}; expected 1 "
        "— this is the W?? regression where Python _restore_utxos_from_block "
        "dropped height on the floor."
    )
    assert restored.is_coinbase is True, (
        "restored UTXO has is_coinbase=False; expected True — this is "
        "the matured-coinbase consensus regression."
    )
    assert int(restored.amount) == cb1_value
    assert bytes(restored.script_pubkey) == op_true_spk


def test_disconnect_block_is_idempotent_for_subsequent_connect(tmp_path) -> None:
    """After disconnect, the block can be reconnected via the raw bytes.

    This proves the new ``_handle_reorg`` connect path: feed the bytes
    we got from ``get_block_bytes`` back into ``connect_block_from_bytes``.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    if not hasattr(sync.PyBlockchainDB, "get_block_bytes"):
        pytest.skip("PyBlockchainDB.get_block_bytes not built into the extension")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    op_true_spk = b"\x51"
    cb_value = 50 * 100_000_000
    block1, block1_hash, _cb_txid, _ = _build_block_with_coinbase(
        prev_hash=genesis_hash,
        height=1,
        timestamp=1296688700,
        cb_outputs=[(cb_value, op_true_spk)],
    )
    db.connect_block_from_bytes(block1, 1)

    # Round-trip: fetch raw bytes, disconnect, then reconnect from the
    # round-tripped bytes.  Tip should match before and after.
    raw = db.get_block_bytes(block1_hash)
    assert raw is not None
    raw = bytes(raw)
    assert raw == block1, "get_block_bytes must round-trip the original block"

    db.disconnect_block(1)
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 0
    assert tip_hash == genesis_hash

    db.connect_block_from_bytes(raw, 1)
    tip_hash, tip_height = db.get_best_block()
    assert tip_height == 1
    assert tip_hash == block1_hash
