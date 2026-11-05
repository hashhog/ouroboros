"""submitblock answers "inconclusive" for a block it stores but does not
connect, and "duplicate" when that block is submitted again, like Core
(fleet item refill-20261102-ouroboros-consensus).

Core rpc/mining.cpp ``submitblock`` (v31.1):

    bool accepted = chainman.ProcessNewBlock(blockptr, ..., &new_block);
    if (!new_block && accepted) return "duplicate";
    if (!sc->found) return "inconclusive";
    return BIP22ValidationResult(sc->state);

``sc->found`` is set by the ``BlockChecked`` signal, which only fires from
``ConnectBlock``.  A block that ``AcceptBlock`` stores on a side branch with
no more work than the tip is never connected, so the answer is
"inconclusive" -- even when the block would fail ConnectBlock, because that
check never ran.  A second submission finds the block already stored
(``fAlreadyHave``): accepted, not new, "duplicate".

Before the fix ouroboros returned null (accepted and connected) for the
stored-only block and "duplicate-inconclusive" for the resubmission
(tools/core-regtest rows chain/submit/side-branch,
*_invalidated_submit/submit/{inconclusive,failed-connect-sibling,
inconclusive-resubmit}, failed_reorg/{a/sibling-3s,b/b3s,b/b4s,b/b5s_bad}).
These tests drive the production RPC handler against the real Rust DB, the
way tools/core-regtest does.
"""

from __future__ import annotations

import asyncio

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import COIN  # noqa: E402
from tests.test_invalidateblock_best_chain import TIP, _block, _setup  # noqa: E402


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _submit(server, raw: bytes):
    return asyncio.run(server.rpc_submitblock(raw.hex()))


def test_side_branch_equal_work_is_inconclusive(tmp_path):
    """chain/submit/side-branch: a sibling of the tip has equal work, so it
    is stored and not connected.  Core: "inconclusive"."""
    bdb, server, hashes = _setup(tmp_path)
    raw, h = _block(hashes[TIP - 1], TIP, b"\x51\xb7")
    assert _submit(server, raw) == "inconclusive"
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    assert h in server._side_branch_blocks


def test_side_branch_lighter_is_inconclusive(tmp_path):
    """A block on a fork two below the tip has less work: stored only."""
    bdb, server, hashes = _setup(tmp_path)
    raw, _ = _block(hashes[TIP - 2], TIP - 1, b"\x52\xb7")
    assert _submit(server, raw) == "inconclusive"
    assert bdb.get_best_block() == (hashes[TIP], TIP)


def test_side_branch_resubmit_is_duplicate(tmp_path):
    """*_invalidated_submit/submit/inconclusive-resubmit: the stored block
    submitted again is accepted and not new.  Core: "duplicate", not
    "duplicate-inconclusive" (which v31.1 only emits from getblocktemplate
    proposal mode)."""
    bdb, server, hashes = _setup(tmp_path)
    raw, _ = _block(hashes[TIP - 1], TIP, b"\x53\xb7")
    assert _submit(server, raw) == "inconclusive"
    assert _submit(server, raw) == "duplicate"
    assert bdb.get_best_block() == (hashes[TIP], TIP)


def test_side_branch_invalid_unconnected_is_inconclusive_not_accepted(tmp_path):
    """failed_reorg/b/b5s_bad: a side block that would fail ConnectBlock
    (bad-cb-amount) but has no more work than the tip is never connected,
    so Core never checks it: "inconclusive".  It must not become the tip,
    and once a child makes the branch heavier the reorg must still refuse
    it -- the answer changed, the validation did not."""
    bdb, server, hashes = _setup(tmp_path)
    bad_raw, bad = _block(hashes[TIP - 1], TIP, b"\x54\xb7", value=51 * COIN)
    assert _submit(server, bad_raw) == "inconclusive"
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    child_raw, _ = _block(bad, TIP + 1, b"\x55\xb7")
    res = _submit(server, child_raw)
    assert res not in (None, "inconclusive", "duplicate"), res
    assert bdb.get_best_block() == (hashes[TIP], TIP)


def test_heavier_side_branch_that_connects_is_null(tmp_path):
    """Control: a side branch that becomes heavier is connected by the
    reorg, BlockChecked fires for the submitted block, Core answers null.
    The stored-only sibling before it is still "inconclusive"."""
    bdb, server, hashes = _setup(tmp_path)
    raw1, h1 = _block(hashes[TIP - 1], TIP, b"\x56\xb7")
    assert _submit(server, raw1) == "inconclusive"
    raw2, h2 = _block(h1, TIP + 1, b"\x57\xb7")
    assert _submit(server, raw2) is None
    assert bdb.get_best_block() == (h2, TIP + 1)


def test_extending_the_tip_is_null(tmp_path):
    """Control: the ordinary fast path (prev == tip) stays null."""
    bdb, server, hashes = _setup(tmp_path)
    raw, h = _block(hashes[TIP], TIP + 1, b"\x58\xb7")
    assert _submit(server, raw) is None
    assert bdb.get_best_block() == (h, TIP + 1)


def test_attach_side_branch_contract_unchanged_for_p2p(tmp_path):
    """The P2P fork bridge (block_sync ``_route_fork_through_reorg_engine``)
    reads any non-None result of ``_attach_side_branch_block`` as a reject
    and drops the bridge / punishes the peer.  The "inconclusive" mapping
    therefore lives in rpc_submitblock only; the engine still returns None
    for a stored-only block."""
    bdb, server, hashes = _setup(tmp_path)
    raw, h = _block(hashes[TIP - 1], TIP, b"\x59\xb7")
    res = asyncio.run(server._attach_side_branch_block(
        bdb, raw, h, hashes[TIP - 1], TIP))
    assert res is None
    assert bdb.get_best_block() == (hashes[TIP], TIP)
