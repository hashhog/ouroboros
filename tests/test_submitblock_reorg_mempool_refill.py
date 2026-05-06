"""Pattern B miswire fix verification — submitblock-driven reorg refills mempool.

Companion test for the fix landed against the dispatch
``Pattern B Tier A miswire`` (CORE-PARITY-AUDIT/_mempool-refill-on-reorg-
fleet-result-2026-05-05.md).

Background
----------
``BlockSync._handle_reorg`` (block_sync.py:2295-2563) refills the mempool with
non-coinbase txs from disconnected blocks after a P2P-driven reorg, mirroring
Bitcoin Core's ``MaybeUpdateMempoolForReorg`` (validation.cpp).

Today's c822cc1 introduced a separate ``RPCServer._reorg_to_side_branch_tip``
(rpc.py:3939+) for submitblock-driven reorgs.  As shipped, that helper called
``db.disconnect_block`` directly without the matching mempool refill loop, so
every transaction in the displaced A-chain silently vanished on a
submitblock-driven reorg.

The fix wires the same mempool refill semantics into the submitblock path:
capture non-coinbase txs from each block-to-disconnect BEFORE the disconnect
loop fires, then call ``self.node.mempool.add_transaction(tx, final_height)``
for each captured tx after the connect loop completes.

This unit test exercises the helper with mocked db / mempool / accept_block so
the assertion is on the contract — disconnected non-coinbase txs MUST be fed
back to the mempool — not on the regtest end-to-end behaviour (covered by the
diff-test corpus entry ``mempool-refill-on-reorg``).
"""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Importing the module triggers the conftest sync-stub install + ouroboros
# package init.  We patch ``accept_block`` at module scope to avoid driving
# actual block validation in this unit test.
import ouroboros.rpc as rpc_module
from ouroboros.rpc import RPCServer


def _fake_tx(txid_hex: str, is_coinbase: bool = False) -> SimpleNamespace:
    """Return a duck-typed Transaction object good enough for the refill loop.

    The refill loop only touches ``tx.is_coinbase`` and
    ``tx.get_txid().hex()`` — no script eval, no serialization.
    """
    raw_id = bytes.fromhex(txid_hex)
    return SimpleNamespace(
        is_coinbase=is_coinbase,
        get_txid=lambda b=raw_id: b,
    )


def _fake_block(*txs) -> SimpleNamespace:
    """Mimic the ``Block`` shape ``db.get_block_by_height`` returns."""
    return SimpleNamespace(transactions=list(txs))


def _make_server_with_side_branch(
    *,
    active_blocks: dict[int, SimpleNamespace],
    side_branch: dict[bytes, tuple[bytes, int, bytes]],
    common_ancestor_hash: bytes,
    common_ancestor_height: int,
    new_tip_hash: bytes,
    final_height_after_connect: int,
):
    """Construct an RPCServer-shaped object with mocked deps for refill test.

    Returns ``(server, mempool_mock, db_mock, accept_block_calls)``.
    """
    # Mempool stub: track add_transaction calls so the test can assert which
    # txs were re-fed.
    mempool = MagicMock()
    mempool.add_transaction.return_value = (True, "")

    # Node stub holding the mempool reference (matches RPCServer.node usage).
    node = SimpleNamespace(mempool=mempool)

    # DB stub: get_best_block returns active tip pre-reorg, then
    # final-height-after-connect post-connect (the refill reads it from
    # the second call).  We model that by tracking a counter.
    db = MagicMock()
    db.get_block_by_height.side_effect = lambda h: active_blocks.get(h)
    # Use a list to flip after the connect loop runs.
    initial_tip_height = max(active_blocks.keys())
    best_calls = {"n": 0}

    def _get_best_block():
        # Pre-disconnect: active tip.  Post-connect (after disconnect_block
        # fires N times + accept_block fires M times): final_height.
        # We don't actually need to be precise across the call chain —
        # the refill code only needs the height to be a sane non-negative
        # int when calling ``add_transaction``.
        best_calls["n"] += 1
        if best_calls["n"] == 1:
            return (b"\xff" * 32, initial_tip_height)
        return (new_tip_hash, final_height_after_connect)

    db.get_best_block.side_effect = _get_best_block
    db.disconnect_block.return_value = b"\x00" * 32
    # Pattern D atomic-disconnect helper — return one fake hash per
    # disconnected height so the per-call shape mirrors what the live
    # Rust extension returns.
    def _disconnect_blocks_atomic(tip_h: int, anc_h: int):
        return [b"\x00" * 32 for _ in range(tip_h - anc_h)]

    db.disconnect_blocks_atomic.side_effect = _disconnect_blocks_atomic

    # Pattern D D-FULL — atomic-connect helper. For multi-block reorgs the
    # connect side now batches every block into a single ``WriteBatch``.
    # Return one fake hash per (raw_bytes, height) pair so the per-call
    # shape mirrors what the live Rust extension returns.
    def _connect_blocks_atomic(blocks, network):
        return [b"\x00" * 32 for _ in blocks]

    db.connect_blocks_atomic.side_effect = _connect_blocks_atomic
    # Mock validate_block_from_bytes to a no-op so the pre-flight pass
    # doesn't reject our opaque raw_bytes.
    db.validate_block_from_bytes.return_value = None

    db.find_height_of_hash.side_effect = lambda h, tip: (
        common_ancestor_height if h == common_ancestor_hash else None
    )
    db.get_block_hash_by_height.side_effect = lambda h: (
        common_ancestor_hash if h == common_ancestor_height else None
    )

    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.node.db = db  # _resolve_parent_height reads node.db in some paths
    server._side_branch_blocks = dict(side_branch)
    server._side_branch_max_entries = 1024

    # Override _resolve_parent_height to return the ancestor height for the
    # ancestor hash, None otherwise — keeps the test deterministic and
    # decoupled from the FFI fallback walk.
    def _resolve_parent_height(_db, prev_hash):
        if prev_hash == common_ancestor_hash:
            return common_ancestor_height
        return None

    server._resolve_parent_height = _resolve_parent_height  # type: ignore[assignment]

    # Track accept_block calls so the test can verify the connect loop ran.
    accept_calls: list[tuple[bytes, int]] = []

    async def _fake_accept_block(db_arg, node_arg, raw_bytes, next_height, *, skip_scripts=False):
        # Match the real accept_block signature; just record the call.
        accept_calls.append((raw_bytes, next_height))
        return b"\x00" * 32

    return server, mempool, db, accept_calls, _fake_accept_block


def test_reorg_to_side_branch_tip_refills_mempool_with_disconnected_txs(monkeypatch):
    """The submitblock reorg path MUST refill mempool with non-coinbase
    disconnected txs.

    Setup:
      - Active chain ends at h=112.  A1 (h=111) contains coinbase + T1.
        A2 (h=112) contains coinbase + T2.
      - Side branch from h=110: B1 (h=111), B2 (h=112), B3 (h=113), all
        coinbase-only.  B-chain is heavier (113 > 112).

    Drive ``_reorg_to_side_branch_tip(db, B3.hash)`` and assert that
    ``mempool.add_transaction`` was called once for T1 and once for T2 —
    matching Bitcoin Core's MaybeUpdateMempoolForReorg behaviour and the
    canonical reference at camlcoin/lib/sync.ml:2354-2363.
    """
    # Hashes (just need 32 distinct bytes; not a real PoW chain).
    ancestor_h = b"\xa0" + b"\x00" * 31
    a1_hash = b"\xa1" + b"\x00" * 31
    a2_hash = b"\xa2" + b"\x00" * 31
    b1_hash = b"\xb1" + b"\x00" * 31
    b2_hash = b"\xb2" + b"\x00" * 31
    b3_hash = b"\xb3" + b"\x00" * 31

    # T1, T2: non-coinbase txs in A1, A2 respectively.  These are the txs
    # that MUST be refilled to the mempool after the reorg.
    t1 = _fake_tx("ab" * 32, is_coinbase=False)
    t2 = _fake_tx("c8" * 32, is_coinbase=False)
    cb_a1 = _fake_tx("11" * 32, is_coinbase=True)
    cb_a2 = _fake_tx("22" * 32, is_coinbase=True)

    active_blocks = {
        # 110: ancestor — never read by the refill loop because the loop
        # walks (current_height, common_ancestor_height, -1) exclusive
        # of the ancestor.
        111: _fake_block(cb_a1, t1),
        112: _fake_block(cb_a2, t2),
    }

    side_branch = {
        b1_hash: (ancestor_h, 111, b"\x01\x02\x03"),  # raw_bytes is opaque to refill
        b2_hash: (b1_hash,    112, b"\x04\x05\x06"),
        b3_hash: (b2_hash,    113, b"\x07\x08\x09"),
    }

    server, mempool, db, accept_calls, fake_accept = _make_server_with_side_branch(
        active_blocks=active_blocks,
        side_branch=side_branch,
        common_ancestor_hash=ancestor_h,
        common_ancestor_height=110,
        new_tip_hash=b3_hash,
        final_height_after_connect=113,
    )

    # Patch accept_block at module scope so the connect loop is harness-
    # safe (no actual block validation).
    monkeypatch.setattr(rpc_module, "accept_block", fake_accept)

    result = asyncio.run(server._reorg_to_side_branch_tip(db, b3_hash))

    # Reorg drive returned None (success / accept).
    assert result is None, f"reorg returned non-None: {result!r}"

    # Pattern D D-FULL — multi-block reorgs route through the atomic
    # connect helper, NOT the per-block accept_block path. Pre-D-FULL
    # this fired ``accept_block`` 3 times (one per side-branch block);
    # post-D-FULL the connect side is a single ``connect_blocks_atomic``
    # call covering all 3 blocks in one ``WriteBatch``.
    assert len(accept_calls) == 0, (
        f"per-block accept_block leaked through the D-FULL connect path; "
        f"this regresses Pattern D back to M batches. Got {len(accept_calls)} calls."
    )
    atomic_connect_calls = db.connect_blocks_atomic.call_args_list
    assert len(atomic_connect_calls) == 1, (
        f"expected exactly one connect_blocks_atomic call; got "
        f"{len(atomic_connect_calls)}"
    )
    # The blocks_arg is a list of (raw_bytes, height) tuples in forward
    # chain order (B1, B2, B3 at heights 111, 112, 113).
    submitted_blocks = atomic_connect_calls[0].args[0]
    submitted_heights = [h for (_, h) in submitted_blocks]
    assert submitted_heights == [111, 112, 113], (
        f"expected connect-batch heights [111,112,113]; got {submitted_heights}"
    )

    # Pattern D — disconnect side fires ONCE via the atomic helper,
    # covering the full range (tip=112, ancestor=110) in a single
    # RocksDB WriteBatch. Pre-fix this was a per-height
    # ``db.disconnect_block(112)`` then ``db.disconnect_block(111)``
    # loop; post-fix it is one ``disconnect_blocks_atomic(112, 110)``
    # call. Per-block ``disconnect_block`` MUST NOT have been called.
    assert db.disconnect_block.call_count == 0, (
        "per-block disconnect_block leaked through the atomic path; "
        "this regresses Pattern D back to N batches."
    )
    atomic_calls = [
        (c.args[0], c.args[1]) for c in db.disconnect_blocks_atomic.call_args_list
    ]
    assert atomic_calls == [(112, 110)], (
        f"expected single atomic disconnect (112, 110); got {atomic_calls}"
    )

    # *** The Pattern B assertion ***
    # mempool.add_transaction was called for T1 and T2 exactly once each.
    # Coinbase txs MUST NOT be refilled (Core never does, and they'd fail
    # standardness).
    refilled_txs = [c.args[0] for c in mempool.add_transaction.call_args_list]
    refilled_txids = {tx.get_txid() for tx in refilled_txs}
    assert refilled_txids == {t1.get_txid(), t2.get_txid()}, (
        f"expected mempool refill of {{T1, T2}}; got "
        f"{[tx.get_txid().hex()[:8] for tx in refilled_txs]}"
    )

    # Coinbase txs must NOT have been refilled.
    for tx in refilled_txs:
        assert not getattr(tx, "is_coinbase", False), (
            "coinbase tx leaked into mempool refill — violates Core parity"
        )


def test_reorg_to_side_branch_tip_no_mempool_refill_when_no_mempool(monkeypatch):
    """Refill loop must be a no-op when ``self.node.mempool`` is None.

    Some test rigs (and the regtest IBD smoke harness) construct a node
    without a mempool.  The reorg path MUST still complete — refill is
    best-effort, not load-bearing for chain state correctness.
    """
    ancestor_h = b"\xa0" + b"\x00" * 31
    b1_hash = b"\xb1" + b"\x00" * 31
    b2_hash = b"\xb2" + b"\x00" * 31

    cb_a1 = _fake_tx("11" * 32, is_coinbase=True)
    t_a1 = _fake_tx("aa" * 32, is_coinbase=False)
    active_blocks = {111: _fake_block(cb_a1, t_a1)}

    side_branch = {
        b1_hash: (ancestor_h, 111, b"\x01"),
        b2_hash: (b1_hash,    112, b"\x02"),
    }

    server, _mempool, db, accept_calls, fake_accept = _make_server_with_side_branch(
        active_blocks=active_blocks,
        side_branch=side_branch,
        common_ancestor_hash=ancestor_h,
        common_ancestor_height=110,
        new_tip_hash=b2_hash,
        final_height_after_connect=112,
    )
    # Drop the mempool to simulate the bare-bones node case.
    server.node.mempool = None

    monkeypatch.setattr(rpc_module, "accept_block", fake_accept)

    result = asyncio.run(server._reorg_to_side_branch_tip(db, b2_hash))
    assert result is None
    # Pattern D D-FULL — connect side now batches via connect_blocks_atomic.
    # Per-block accept_block MUST NOT have fired.
    assert len(accept_calls) == 0
    atomic_connect_calls = db.connect_blocks_atomic.call_args_list
    assert len(atomic_connect_calls) == 1
    submitted_blocks = atomic_connect_calls[0].args[0]
    submitted_heights = [h for (_, h) in submitted_blocks]
    assert submitted_heights == [111, 112], (
        f"expected connect-batch heights [111,112]; got {submitted_heights}"
    )
    # Pattern D — disconnect side fires once via the atomic helper.
    assert db.disconnect_block.call_count == 0
    atomic_calls = [
        (c.args[0], c.args[1]) for c in db.disconnect_blocks_atomic.call_args_list
    ]
    assert atomic_calls == [(111, 110)]
