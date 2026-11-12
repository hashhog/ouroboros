"""BIP157 filter headers chain from the block's parent after a tip change
(fleet item sm-fix-ouroboros-filter-header-reorg).

A filter header is ``dSHA256(filter_hash || parent's filter header)``
(BIP157).  ``PersistentBlockFilterIndex.add`` used the header of the block
ADDED LAST.  The RPC reorg engine and invalidateblock disconnect without
rewinding the index, so the first block connected afterwards chained off the
old tip's header, and every later header inherited the error (and persisted
on disk).  Core rewinds the index to ``pindex->pprev`` before connecting
(index/base.cpp ``BaseIndex::BlockConnected`` -> ``Rewind``), and
``BlockFilterIndex::CustomRemove`` resets ``m_last_header`` to the parent's
header (index/blockfilterindex.cpp).

The reorg-onto-a-heavier-side-branch case is
``tests/test_sm_sweep_reorg.py::test_sm_sweep_filter_header_after_reorg_chains_from_fork_point``.
This file covers the invalidateblock variants, restart persistence, and the
in-memory fallback index.  These drive the production RPC handlers against
the real Rust DB.
"""

from __future__ import annotations

import asyncio

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests.test_invalidateblock_best_chain import (  # noqa: E402
    TIP,
    _block,
    _disp,
    _side_branch,
)
from tests.test_invalidateblock_best_chain import _setup as _bc_setup  # noqa: E402


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _expected_header(bdb, block_hash: bytes, prev_header: bytes) -> bytes:
    from ouroboros.blockfilter import build_basic_filter, compute_filter_header

    blk = bdb.get_block(block_hash)
    return compute_filter_header(build_basic_filter(blk, bdb), prev_header)


def _indexed_setup(tmp_path, enabled: bool = True):
    from ouroboros.blockfilter import PersistentBlockFilterIndex

    bdb, server, hashes = _bc_setup(tmp_path)
    bfi = PersistentBlockFilterIndex(str(tmp_path / "bfi"), enabled=enabled)
    for h in range(TIP + 1):
        bfi.add_block(bdb.get_block_by_height(h), h, bdb)
    server.node.block_filter_index = bfi
    return bdb, server, hashes, bfi


def _assert_chain_from_parent(bdb, bfi, block_hash: bytes, parent: bytes):
    parent_header = bfi.get_header(parent)
    assert parent_header is not None, "precondition: parent is indexed"
    assert bfi.get_header(block_hash) == _expected_header(
        bdb, block_hash, parent_header
    ), "filter header does not chain from the block's parent"


def test_invalidateblock_then_child_of_new_tip_chains_from_its_parent(tmp_path):
    """invalidateblock TIP with no side branch: the tip falls back to TIP-1.
    A block mined on TIP-1 must chain from TIP-1's filter header, not from
    the invalidated TIP's (the header added last)."""
    bdb, server, hashes, bfi = _indexed_setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (hashes[TIP - 1], TIP - 1), (
        "precondition: tip moved back to the invalidated block's parent")

    raw, child = _block(hashes[TIP - 1], TIP, bytes([0x61, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    assert bdb.get_best_block() == (child, TIP), "precondition: child is tip"
    _assert_chain_from_parent(bdb, bfi, child, hashes[TIP - 1])

    # And the next block keeps chaining off the corrected header.
    raw2, grandchild = _block(child, TIP + 1, bytes([0x62, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw2.hex())) is None
    _assert_chain_from_parent(bdb, bfi, grandchild, child)


def test_invalidateblock_switch_to_side_branch_chains_from_fork_point(tmp_path):
    """invalidateblock TIP with a stored equal-work side branch off TIP-2:
    the engine connects 5'-6' (Core activates the best valid chain).  5'
    chains from 4's header, 6' from 5', and a child of 6' from 6'."""
    bdb, server, hashes, bfi = _indexed_setup(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x40)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (side[-1], TIP), "precondition: reorged"

    _assert_chain_from_parent(bdb, bfi, side[0], hashes[TIP - 2])
    _assert_chain_from_parent(bdb, bfi, side[1], side[0])

    raw, child = _block(side[-1], TIP + 1, bytes([0x63, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    _assert_chain_from_parent(bdb, bfi, child, side[-1])


def test_corrected_headers_persist_and_chain_after_reopen(tmp_path):
    """The headers written after the reorg are what a restarted node reads,
    and a block connected after the reopen still chains from its parent."""
    from ouroboros.blockfilter import PersistentBlockFilterIndex

    bdb, server, hashes, bfi = _indexed_setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    raw, child = _block(hashes[TIP - 1], TIP, bytes([0x64, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None

    reopened = PersistentBlockFilterIndex(str(tmp_path / "bfi"))
    _assert_chain_from_parent(bdb, reopened, child, hashes[TIP - 1])

    server.node.block_filter_index = reopened
    raw2, grandchild = _block(child, TIP + 1, bytes([0x65, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw2.hex())) is None
    _assert_chain_from_parent(bdb, reopened, grandchild, child)


def test_in_memory_fallback_index_chains_from_parent(tmp_path):
    """The enabled=False fallback (in-memory BlockFilterIndex) had the same
    last-added chaining; it must follow the parent too."""
    bdb, server, hashes, bfi = _indexed_setup(tmp_path, enabled=False)
    assert bfi._memory_index is not None, "precondition: in-memory fallback"
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    raw, child = _block(hashes[TIP - 1], TIP, bytes([0x66, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    _assert_chain_from_parent(bdb, bfi, child, hashes[TIP - 1])


def test_control_stale_tip_chaining_is_detected(tmp_path):
    """Negative control for the assertion helper: a header chained off the
    invalidated tip (what the old code produced) differs from the
    parent-chained one, so the tests above can tell the two apart."""
    from ouroboros.blockfilter import build_basic_filter, compute_filter_header

    bdb, server, hashes, bfi = _indexed_setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    raw, child = _block(hashes[TIP - 1], TIP, bytes([0x67, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    filt = build_basic_filter(bdb.get_block(child), bdb)
    stale = compute_filter_header(filt, bfi.get_header(hashes[TIP]))
    fresh = compute_filter_header(filt, bfi.get_header(hashes[TIP - 1]))
    assert stale != fresh


def test_control_genesis_and_fresh_index_unchanged(tmp_path):
    """Control: genesis (parent never indexed) still chains from 0^32, so a
    fresh index's header chain is unchanged by the parent lookup."""
    bdb, server, hashes, bfi = _indexed_setup(tmp_path)
    assert bfi.get_header(hashes[0]) == _expected_header(
        bdb, hashes[0], b"\x00" * 32)
    for h in range(1, TIP + 1):
        _assert_chain_from_parent(bdb, bfi, hashes[h], hashes[h - 1])
