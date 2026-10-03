"""A consensus-invalid block delivered over P2P (Core parity).

Bitcoin Core, for a block a peer delivers that fails ConnectBlock /
ContextualCheckBlock (BLOCK_CONSENSUS):
  * ``Chainstate::InvalidBlockFound`` marks it BLOCK_FAILED_VALID and
    ``InvalidChainFound`` marks every descendant BLOCK_FAILED_CHILD; the block
    is never requested again and ActivateBestChain moves on to the most-work
    VALID chain (a same-height competitor is fetched).
  * ``MaybePunishNodeForBlock`` (via ``BlockChecked`` / mapBlockSource)
    Misbehaving()s the peer that delivered it.
  * A later header for the failed block is ``duplicate-invalid``
    (BLOCK_CACHED_INVALID: only an OUTBOUND peer is punished), a header whose
    parent is failed is ``bad-prevblk`` (BLOCK_INVALID_PREV: punished).
  * NON-verdicts are not marked: BLOCK_MUTATED (bad merkle root, witness
    malleation — the sender is punished but the hash stays fetchable) and
    "cannot decide yet" errors (missing ancestor header, missing parent).

Pre-fix ouroboros kept a rejected block in slot 0 of the header queue (the
head-of-window re-requested it forever while redeliveries were dropped), never
punished the sender, and on the fork path simply forgot the fork, so the next
announcement re-fetched the same invalid body.  Peer block handlers were also
attached only on the next sync_loop tick, so a new peer's first announcement
was dropped unseen.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

import ouroboros.block_sync as _bsmod  # noqa: E402
from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import HeadersMessage, NetworkMessage  # noqa: E402
from ouroboros.tests.test_p2p_fork_reorg import (  # noqa: E402
    REGTEST_BITS,
    _FakeReorgServer,
    _fresh,
    _mine_fork,
)


# ---------------------------------------------------------------------------
# Drain path (block extends the tip-anchored header queue)
# ---------------------------------------------------------------------------


def _drain_bs() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    pm = MagicMock()
    pm.misbehaving = MagicMock(return_value=True)
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    bs._prebase_headers_complete = True
    return bs


def _stage(bs: BlockSync, block_hash: bytes, child_hash: bytes,
           src: str = "127.0.0.2:5555") -> None:
    """B1 at queue slot 0 (tip+1, buffered + requested), B2 on top of it at
    slot 1.  Height 1 is below BIP34 so the drain goes straight to validate."""
    tip_hash, _ = bs.db.get_best_block.return_value
    h1 = MagicMock()
    h1.prev_blockhash = tip_hash
    h2 = MagicMock()
    h2.prev_blockhash = block_hash
    bs._validated_headers = [(block_hash, h1), (child_hash, h2)]
    cb_in = MagicMock()
    cb_in.script_sig = bytes([0x00, 0x00])
    cb = MagicMock()
    cb.inputs = [cb_in]
    blk = MagicMock()
    blk.transactions = [cb]
    bs._ibd_block_buffer[block_hash] = (blk, b"\x00" * 80)
    bs.requested_blocks[block_hash] = 1.0
    bs._block_source_peer_addr[block_hash] = src


@pytest.mark.asyncio
async def test_drain_consensus_reject_marks_failed_and_punishes(monkeypatch):
    """bad-cb-amount at tip+1: the block and its queued descendant are marked
    failed, dropped from the header queue (so a same-height competitor can be
    queued), never re-requested, and the delivering peer is punished."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x11" * 32, b"\x12" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Coinbase amount invalid")
    )

    await bs._drain_block_buffer_locked()

    # Queue no longer holds the failed block or anything built on it.
    assert bs._validated_headers == []
    # Never fetched again (inv / head-of-window / handle_block gates).
    assert b1 in bs._perm_rejected_blocks
    assert b2 in bs._perm_rejected_blocks
    assert b1 not in bs.requested_blocks
    # The sender is punished (Core MaybePunishNodeForBlock, BLOCK_CONSENSUS).
    bs.peer_manager.misbehaving.assert_called_once()
    addr, score, _reason = bs.peer_manager.misbehaving.call_args.args
    assert addr == "127.0.0.2:5555"
    assert score >= 100
    assert getattr(bs, "_failed_blocks", set()) >= {b1, b2}


@pytest.mark.asyncio
async def test_drain_mutated_block_is_not_marked_failed(monkeypatch):
    """NON-VERDICT: BLOCK_MUTATED (merkle root mismatch).  The bytes do not
    match the header, so the hash must stay fetchable (Core re-requests it
    from another peer); only the sender is punished."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x21" * 32, b"\x22" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Invalid merkle root")
    )

    await bs._drain_block_buffer_locked()

    assert b1 not in bs._perm_rejected_blocks
    assert b1 not in getattr(bs, '_failed_blocks', set())
    # Still the head of the queue -> re-fetched from a peer.
    assert bs._validated_headers[0][0] == b1
    assert b1 not in bs.requested_blocks
    bs.peer_manager.misbehaving.assert_called_once()


@pytest.mark.asyncio
async def test_drain_missing_ancestor_is_held_not_marked(monkeypatch):
    """NON-VERDICT: the BIP68 'cannot decide yet' hold (MissingAncestorHeader).
    Re-buffered, not marked, nobody punished."""
    from ouroboros.validation import MissingAncestorHeaderError

    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x31" * 32, b"\x32" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(
        side_effect=MissingAncestorHeaderError("coin MTP ancestor not held")
    )

    await bs._drain_block_buffer_locked()

    assert b1 not in bs._perm_rejected_blocks
    assert b1 not in getattr(bs, '_failed_blocks', set())
    assert b1 in bs._ibd_block_buffer
    assert [h for h, _ in bs._validated_headers] == [b1, b2]
    bs.peer_manager.misbehaving.assert_not_called()


def test_classifier():
    v = getattr(_bsmod, "classify_block_reject", None)
    assert v is not None, "block_sync.classify_block_reject missing"
    # verdicts (Python and Rust-FFI wording)
    assert v("Coinbase amount invalid") == "verdict"
    assert v("validate: Coinbase amount exceeds subsidy + fees") == "verdict"
    assert v("Transaction 1 invalid: BIP 68 sequence lock not satisfied") == "verdict"
    assert v("bad-txns-nonfinal") == "verdict"
    assert v("BIP30: duplicate unspent txid") == "verdict"
    # BLOCK_MUTATED
    assert v("Invalid merkle root") == "mutated"
    assert v("validate: Duplicate transaction detected") == "mutated"
    assert v("bad-witness-merkle-match") == "mutated"
    assert v("validate: BIP141: block has witness data but no witness commitment") == "mutated"
    # cannot decide / not a verdict
    assert v("missing-ancestor-header: coin MTP") == "nonverdict"
    assert v("Previous block not found") == "nonverdict"
    assert v("missing common ancestor 0011") == "nonverdict"
    assert v("time-too-new") == "nonverdict"
    assert v("rocksdb: IO error: No space left on device") == "nonverdict"
    assert v("") == "nonverdict"


# ---------------------------------------------------------------------------
# Fork path (equal-work announcement, then a heavier extension on top of it)
# ---------------------------------------------------------------------------


class _RejectingReorgServer(_FakeReorgServer):
    """The real engine's contract on a connect failure: roll back, record
    (failing hash, error) in ``_last_reorg_failure``, return the BIP-22
    token."""

    def __init__(self, db, fail_index: int, error: str):
        super().__init__(db)
        self.fail_index = fail_index
        self.error = error
        self._last_reorg_failure = None

    async def _reorg_to_side_branch_tip(self, db, new_tip_hash):
        self.reorg_calls.append(new_tip_hash)
        chain_rev = []
        cursor = new_tip_hash
        while cursor in self._side_branch_blocks:
            chain_rev.append(cursor)
            cursor = self._side_branch_blocks[cursor][0]
        chain = list(reversed(chain_rev))
        self._last_reorg_failure = (chain[self.fail_index], self.error)
        return "bad-cb-amount"


class TestForkPathInvalid(unittest.IsolatedAsyncioTestCase):
    async def _run(self, error: str):
        bs, db, peer, chain = _fresh(chain_len=2)  # active tip h=1
        # Header context the fork-store admission needs (parent bits/time for
        # bad-diffbits, cumulative work for the strictly-heavier compare).
        _hdr = SimpleNamespace(bits=REGTEST_BITS, timestamp=1_600_000_000,
                               prev_blockhash=bytes(32))
        db.get_block_by_height = lambda h: _hdr
        db.get_block_header = lambda hh: _hdr
        db.get_block = lambda hh: _hdr
        db.get_chainwork_by_height = lambda h: 2 * (h + 1)
        punished = []
        bs.peer_manager.misbehaving = lambda addr, score, reason: punished.append(
            (addr, score, reason)) or True
        # B1 (invalid) at h=1 competing with the tip, B2x on top: heavier.
        hdrs, hashes, bodies = _mine_fork(chain[0], 2, base_nonce=40_000)
        srv = _RejectingReorgServer(db, fail_index=0, error=error)
        bs.set_reorg_handler(srv)
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        for hh in hashes:
            await bs.handle_block(
                NetworkMessage(command="block", payload=bodies[hh]), peer)
        return bs, peer, hdrs, hashes, punished, srv

    async def test_failed_fork_block_marked_never_refetched_sender_punished(self):
        bs, peer, hdrs, hashes, punished, srv = await self._run(
            "Coinbase amount exceeds subsidy + fees")
        b1, b2x = hashes
        self.assertEqual(len(srv.reorg_calls), 1)
        self.assertIn(b1, bs._perm_rejected_blocks)
        self.assertIn(b2x, bs._perm_rejected_blocks)  # FAILED_CHILD
        self.assertEqual([p[0] for p in punished], [f"{peer.host}:{peer.port}"])
        # Re-announcement (the sender redials and re-sends headers + inv):
        # nothing is requested and no second reorg is attempted.
        peer.sent.clear()
        bs.requested_blocks.clear()
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        from ouroboros.p2p_messages import InvMessage
        await bs.handle_inv(InvMessage([(2, b1), (2, b2x)]).to_network_message(
            "regtest"), peer)
        self.assertNotIn(b1, bs.requested_blocks)
        self.assertNotIn(b2x, bs.requested_blocks)
        self.assertFalse([m for m in peer.sent if m.command == "getdata"])
        self.assertEqual(len(srv.reorg_calls), 1)

    async def test_cached_invalid_header_inbound_not_punished_outbound_is(self):
        bs, peer, hdrs, hashes, punished, srv = await self._run(
            "Coinbase amount exceeds subsidy + fees")
        punished.clear()
        peer.inbound = True
        await bs.handle_headers(
            HeadersMessage(hdrs[:1]).to_network_message("regtest"),
            peer, min_pow_checked=True)
        self.assertEqual(punished, [])  # BLOCK_CACHED_INVALID, inbound
        peer.inbound = False
        await bs.handle_headers(
            HeadersMessage(hdrs[:1]).to_network_message("regtest"),
            peer, min_pow_checked=True)
        self.assertEqual(len(punished), 1)  # outbound on an invalid chain

    async def test_header_building_on_failed_block_is_bad_prevblk(self):
        bs, peer, hdrs, hashes, punished, srv = await self._run(
            "Coinbase amount exceeds subsidy + fees")
        punished.clear()
        peer.inbound = True
        more, more_hashes, _ = _mine_fork(hashes[-1], 1, base_nonce=41_000)
        await bs.handle_headers(
            HeadersMessage(more).to_network_message("regtest"),
            peer, min_pow_checked=True)
        self.assertEqual(len(punished), 1)  # BLOCK_INVALID_PREV: always
        self.assertIn(more_hashes[0], bs._perm_rejected_blocks)
        self.assertNotIn(more_hashes[0], bs._fork_headers)

    async def test_fork_nonverdict_is_not_marked(self):
        """NON-VERDICT on the fork path: the engine could not decide (missing
        ancestor header).  Nothing marked, nobody punished."""
        bs, peer, hdrs, hashes, punished, srv = await self._run(
            "missing-ancestor-header: coin MTP ancestor not held")
        self.assertEqual(len(srv.reorg_calls), 1)  # the bridge WAS tried
        self.assertNotIn(hashes[0], bs._perm_rejected_blocks)
        self.assertNotIn(hashes[1], bs._perm_rejected_blocks)
        self.assertEqual(punished, [])


# ---------------------------------------------------------------------------
# Handler registration at handshake
# ---------------------------------------------------------------------------


def test_register_peer_attaches_block_handlers_immediately():
    """The node calls BlockSync.register_peer from its inbound/outbound
    handshake hooks, so the peer's FIRST headers/inv/block is handled
    (pre-fix the handlers waited for the next sync_loop tick, up to ~10 s,
    and an announcement sent right after VERACK was dropped as
    'No handler')."""
    bs, db, peer, chain = _fresh(chain_len=2)
    peer.message_handlers = {}
    assert bs.register_peer(peer) is True
    assert {"inv", "block", "headers"} <= set(peer.message_handlers)
    assert bs.register_peer(peer) is False  # idempotent


@pytest.mark.asyncio
async def test_node_handshake_hooks_register_block_sync():
    from ouroboros.node import BitcoinNode

    node = BitcoinNode.__new__(BitcoinNode)
    pm = MagicMock()
    node.peer_manager = pm
    node.block_filter_index = None
    node.block_sync = MagicMock()
    node.mempool = None
    node._register_handlers()
    inbound_hook = pm.set_inbound_peer_handler.call_args.args[0]
    outbound_hook = pm.set_outbound_peer_handler.call_args.args[0]
    p1, p2 = MagicMock(), MagicMock()
    await inbound_hook(p1)
    await outbound_hook(p2)
    node.block_sync.register_peer.assert_any_call(p1)
    node.block_sync.register_peer.assert_any_call(p2)
