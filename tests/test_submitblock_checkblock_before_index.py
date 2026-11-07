"""submitblock reject tokens follow Core's check order.

Core ``ProcessNewBlock`` runs the context-free ``CheckBlock`` before
``AcceptBlock``; the block-index answers ``prev-blk-not-found``,
``bad-prevblk`` and ``duplicate-invalid`` come from ``AcceptBlockHeader``
inside AcceptBlock (validation.cpp).

Core v31.1 regtest rows these pin (tools/core-regtest, ouroboros baseline):
  chain/submit/prev-not-found:$                               prev-blk-not-found
  seed_invalidated_submit/submit/bad-txnmrklroot:$            bad-txnmrklroot
  warden_invalidated_submit/submit/bad-txnmrklroot-on-failed:$ bad-txnmrklroot

Imports of the new module are inside the tests so the file collects on a
tree without it and each test fails by name.
"""

from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import (  # noqa: E402
    BASE_TIME,
    REGTEST_BITS,
    Chain,
    coinbase_tx,
    dsha,
    merkle_root,
    varint,
)

TIP = 10
X = 8  # invalidate block 8 -> tip 7; blocks 8..10 are failed


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _setup(tmp_path, with_validator: bool = False):
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
    node_validator = None
    if with_validator:
        from ouroboros.validation import TransactionValidator

        node_validator = SimpleNamespace(
            tx_validator=TransactionValidator.__new__(TransactionValidator)
        )
    node = SimpleNamespace(network="regtest", validator=node_validator,
                           mempool=None, db=bdb, block_sync=bs,
                           data_dir=str(tmp_path))
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, chain, bs, server, hashes


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def _solve(prev: bytes, root: bytes, timestamp: int, txs, bits: int = REGTEST_BITS,
           want_pow: bool = True):
    """Header over ``txs`` with an explicit merkle ``root``; PoW solved (or
    deliberately failed when ``want_pow`` is False)."""
    for nonce in range(4_000_000):
        header = (struct.pack("<i", 0x20000000) + prev + root
                  + struct.pack("<III", timestamp, bits, nonce))
        h = dsha(header)
        if (h[31] < 0x7F) == want_pow:
            return header + varint(len(txs)) + b"".join(txs), h
    raise RuntimeError("could not solve header")  # pragma: no cover


def _block(prev: bytes, height: int, *, bad_merkle: bool = False, txs=None,
           want_pow: bool = True, tag: bytes = b"\x02T"):
    txs = [coinbase_tx(height, tag=tag)] + list(txs or [])
    root = merkle_root([dsha(t) for t in txs])
    if bad_merkle:
        root = bytes(b ^ 0xFF for b in root)
    return _solve(prev, root, BASE_TIME + height * 600 + 7, txs, want_pow=want_pow)


def _invalidate(server, hashes):
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[X])))


# --- submitblock: failed parent ---------------------------------------------

def test_bad_merkle_block_on_invalidated_parent_is_bad_txnmrklroot(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    _invalidate(server, hashes)
    raw, _ = _block(hashes[TIP], TIP + 1, bad_merkle=True)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-txnmrklroot"
    assert bdb.get_best_block() == (hashes[X - 1], X - 1)


def test_high_hash_block_on_invalidated_parent_is_high_hash(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    _invalidate(server, hashes)
    raw, _ = _block(hashes[TIP], TIP + 1, want_pow=False)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "high-hash"


def test_valid_block_on_invalidated_parent_stays_bad_prevblk(tmp_path):
    # Control: a block that passes CheckBlock keeps AcceptBlockHeader's token.
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    _invalidate(server, hashes)
    raw, _ = _block(hashes[TIP], TIP + 1)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-prevblk"


def test_resubmitted_invalidated_block_stays_duplicate_invalid(tmp_path):
    # Control: the failed block itself (passes CheckBlock) is duplicate-invalid.
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw_x = bytes(bdb.get_block_bytes(hashes[X]))
    _invalidate(server, hashes)
    assert asyncio.run(server.rpc_submitblock(raw_x.hex())) == "duplicate-invalid"


# --- submitblock: unknown parent ----------------------------------------------

def test_unknown_parent_is_prev_blk_not_found(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw, _ = _block(dsha(b"no-such-parent"), TIP + 1)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "prev-blk-not-found"
    assert bdb.get_best_block() == (hashes[TIP], TIP)


def test_bad_merkle_block_on_unknown_parent_is_bad_txnmrklroot(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw, _ = _block(dsha(b"no-such-parent"), TIP + 1, bad_merkle=True)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-txnmrklroot"


def test_checktransaction_failure_on_unknown_parent_is_its_token(tmp_path):
    # A non-coinbase tx with no outputs: CheckTransaction bad-txns-vout-empty
    # (consensus/tx_check.cpp) is reported before prev-blk-not-found.
    from tests._f0_chain import ser_tx

    bdb, chain, bs, server, hashes = _setup(tmp_path, with_validator=True)
    no_out = ser_tx([(dsha(b"some-coin"), 0, b"", 0xFFFFFFFF)], [])
    raw, _ = _block(dsha(b"no-such-parent"), TIP + 1, txs=[no_out])
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-txns-vout-empty"


def test_valid_tip_extension_still_connects(tmp_path):
    # Control: the tip path is untouched; a good child of the tip connects.
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    raw, h = _block(hashes[TIP], TIP + 1)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    assert bdb.get_best_block() == (h, TIP + 1)


# --- Core ComputeMerkleRoot mutation semantics --------------------------------

def test_merkle_mutation_only_for_adjacent_equal_pairs():
    from ouroboros.check_block import compute_merkle_root

    a, b, c = dsha(b"a"), dsha(b"b"), dsha(b"c")
    # [a, b, c]: odd padding duplicates c, which Core does NOT flag.
    root, mutated = compute_merkle_root([a, b, c])
    assert not mutated and root == merkle_root([a, b, c])
    # [a, b, a]: equal txids but not an adjacent pair -> not mutated.
    assert compute_merkle_root([a, b, a])[1] is False
    # [a, b, c, c]: adjacent equal pair -> mutated (CVE-2012-2459), same root
    # as [a, b, c].
    root4, mutated4 = compute_merkle_root([a, b, c, c])
    assert mutated4 and root4 == root
