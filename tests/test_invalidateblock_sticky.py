"""invalidateblock must STICK (audit OU-2, fleet brief #6, 2026-10-07).

Core (validation.cpp InvalidateBlock -> InvalidChainFound ->
RecalculateBestHeader): the block is BLOCK_FAILED_VALID, its descendants
BLOCK_FAILED_CHILD; AcceptBlockHeader refuses a header that is failed
("duplicate-invalid") or builds on a failed one ("bad-prevblk",
BLOCK_INVALID_PREV); submitblock of the failed block answers
"duplicate-invalid"; ReconsiderBlock (ResetBlockFailureFlags) clears the
block, its descendants and ancestors and ActivateBestChain brings it back.

Before the fix rpc_invalidateblock disconnected in Rust but never told
block_sync, so the next announcement of the branch (or a submitblock of it)
reconnected the invalidated block.  These tests drive the production RPC
handlers against the real Rust DB.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import Chain  # noqa: E402

TIP = 10
X = 8  # invalidate block 8 -> tip 7


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _setup(tmp_path):
    from ouroboros.block_sync import BlockSync
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    chain = Chain(bdb._db, tip=TIP)
    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    if hasattr(bs, "load_rpc_invalidated"):
        bs.load_rpc_invalidated(str(tmp_path / "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=str(tmp_path))
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, chain, bs, server, hashes


def _failed(bs, h: bytes) -> bool:
    if hasattr(bs, "is_block_failed"):
        return bs.is_block_failed(h)
    return h in bs._failed_blocks


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def test_invalidate_marks_branch_failed_in_sync_layer(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    assert bdb.get_best_block() == (hashes[X - 1], X - 1)
    for h in range(X, TIP + 1):
        assert _failed(bs, hashes[h]), f"block {h} not failed in block_sync"
    assert not _failed(bs, hashes[X - 1])


def test_submitblock_cannot_reconnect_invalidated_branch(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw_x = bytes(bdb.get_block_bytes(hashes[X]))
    raw_next, _h11 = chain.next_block([])  # child of the old tip (block 10)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    assert asyncio.run(server.rpc_submitblock(raw_x.hex())) == "duplicate-invalid"
    assert asyncio.run(server.rpc_submitblock(raw_next.hex())) == "bad-prevblk"
    assert bdb.get_best_block() == (hashes[X - 1], X - 1), "invalidation undone"


def test_header_on_invalidated_branch_refused(tmp_path):
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage, NetworkMessage

    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw_next, h11 = chain.next_block([])
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    hdr, _ = BlockHeader.from_payload(raw_next[:80], 0)
    peer = MagicMock()
    peer.host, peer.port, peer.inbound = "127.0.0.3", 8333, True
    msg = NetworkMessage(command="headers", payload=HeadersMessage(headers=[hdr]).serialize_payload())
    try:
        asyncio.run(bs.handle_headers(msg, peer))
    except Exception:
        pass
    assert all(h != h11 for h, _ in bs._validated_headers)
    assert _failed(bs, h11), "child of an invalidated block must be BLOCK_FAILED_CHILD"
    reasons = [c.args[2] for c in bs.peer_manager.misbehaving.call_args_list]
    assert "bad-prevblk" in reasons


def test_reconsider_clears_flags_and_reactivates(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw_next, h11 = chain.next_block([])
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    asyncio.run(server.rpc_reconsiderblock(_disp(hashes[X])))
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    for h in range(X, TIP + 1):
        assert not _failed(bs, hashes[h])
    assert asyncio.run(server.rpc_submitblock(raw_next.hex())) is None
    assert bdb.get_best_block() == (h11, TIP + 1)


def test_invalidation_survives_restart(tmp_path):
    from ouroboros.block_sync import BlockSync

    bdb, chain, bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    path = str(tmp_path / "invalidated_blocks.json")
    assert os.path.exists(path)
    bs2 = BlockSync(db=bdb, validator=MagicMock(), peer_manager=MagicMock())
    assert bs2.load_rpc_invalidated(path) == 1
    assert _failed(bs2, hashes[X])
    asyncio.run(server.rpc_reconsiderblock(_disp(hashes[X])))
    bs3 = BlockSync(db=bdb, validator=MagicMock(), peer_manager=MagicMock())
    assert bs3.load_rpc_invalidated(path) == 0


def test_drain_never_connects_a_failed_block(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw_x = bytes(bdb.get_block_bytes(hashes[X]))
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    # Simulate a stale queue entry for the invalidated block at tip+1.
    from ouroboros.p2p_messages import BlockHeader
    hdr, _ = BlockHeader.from_payload(raw_x[:80], 0)
    bs._validated_headers = [(hashes[X], hdr)]
    bs._buffer_put(hashes[X], (None, raw_x))
    try:
        asyncio.run(bs._drain_block_buffer())
    except Exception:
        pass
    assert bdb.get_best_block() == (hashes[X - 1], X - 1)


def _real_mempool(bdb):
    """The real Mempool over the real chain view; consensus script checks
    stubbed (the coins are OP_TRUE).  rpc._update_mempool_after_disconnect
    now drives Mempool.update_for_reorg, so a duck-typed stub would test
    nothing."""
    from ouroboros.mempool import Mempool
    from ouroboros.validation import TransactionValidator

    class _V(TransactionValidator):
        def __init__(self, db):
            self.db = db
            self.network = "regtest"
            self.snapshot_manager = None

        def validate_transaction(self, tx, height, *a, **k):
            return True, ""

    return Mempool(_V(bdb), require_standard=False)


def _spend(prev_txid: bytes, value: int, tag: int):
    import hashlib
    from ouroboros.database import Transaction, TxIn, TxOut
    tx = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=prev_txid, prev_vout=0,
                     script_sig=b"\x51" + bytes([tag]), sequence=0xFFFFFFFE)],
        outputs=[TxOut(value=value, script_pubkey=b"\x51")],
    )
    tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
    return tx


def test_invalidate_updates_mempool_for_reorg(tmp_path):
    """Core MaybeUpdateMempoolForReorg: a pool tx spending a coin the
    disconnect removed (an output of an invalidated block's coinbase) is
    dropped by removeForReorg; one spending a coin still in the UTXO set
    stays."""
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    mp = _real_mempool(bdb)
    server.node.mempool = mp
    cb_x = bdb.get_block_by_height(X).transactions[0].get_txid()
    gone = _spend(cb_x, 1_000, 1)
    kept = _spend(chain.fund[0], 1_000, 2)
    for t in (gone, kept):
        # Bypass ATMP's coinbase-maturity view: the point is what the
        # invalidate does to entries already in the pool.
        ok, err = mp._add_transaction_inner(t, TIP, bypass_limits=True)
        assert ok, err
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))
    assert gone.get_txid() not in mp.transactions, "spend of a disconnected coin left in the pool"
    assert kept.get_txid() in mp.transactions
