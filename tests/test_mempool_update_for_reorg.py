"""Mempool consistent with the chain after a reorg / invalidateblock.

Core ``MaybeUpdateMempoolForReorg`` (validation.cpp) after DisconnectTip(s) and
ConnectTip(s): re-accept the disconnected blocks' txs EARLIEST FIRST
(bypass_limits); a tx that fails is ``removeRecursive``'d — its in-pool
descendants go with it; re-added txs get their existing in-pool children
linked (``UpdateTransactionsFromBlock``); then ``removeForReorg`` drops EVERY
entry that at tip+1 is non-final (BIP113), sequence-locked (BIP68) or spends an
immature coinbase, with its descendants; then ``LimitMempoolSize``.

Deployed ouroboros (46d6a08), observed by tools/mempool-reorg-sweep.py
scenario (c)/(e): after a P2P reorg whose new branch double-spends block tx A1,
A1 was not re-added (correct) but its in-pool child M2 STAYED and
getblocktemplate handed it out — an invalid template.  These tests drive the
real ``Mempool`` through the RPC reorg entry points.
"""

from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import ouroboros.rpc as rpc_module
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool
from ouroboros.rpc import RPCServer
from ouroboros.validation import TransactionValidator

COIN1 = (b"\xc1" * 32, 0)   # spent by block tx A1 on the old branch, by X on the new
COIN_L = (b"\xc2" * 32, 0)  # spent by the time-locked LT
COIN_S = (b"\xc3" * 32, 0)  # spent by the BIP68-locked S
COIN_O = (b"\xc4" * 32, 0)  # bystander
SEQ_FINAL_RBF = 0xFFFFFFFE  # nLockTime enabled, BIP68 disabled (bit 31 set)


def _coin(height: int, coinbase: bool = False) -> dict:
    return {"value": 100_000_000, "script_pubkey": b"\x51", "height": height,
            "is_coinbase": coinbase}


class _StubDB:
    def __init__(self, tip: int) -> None:
        self.tip = tip
        self.utxos: dict = {}

    def get_utxo(self, txid: bytes, vout: int):
        return self.utxos.get((txid, vout))

    def get_best_block(self):
        return (b"\xee" * 32, self.tip)

    def get_median_time_past(self, height: int):
        return 1_700_000_000 + height * 600


class _Validator(TransactionValidator):
    """The real finality / BIP68 helpers, consensus script checks stubbed."""

    def __init__(self, db) -> None:  # noqa: D401 - no ScriptInterpreter needed
        self.db = db
        self.network = "regtest"
        self.snapshot_manager = None

    def validate_transaction(self, tx, height, *a, **k):
        for tx_in in tx.inputs:
            if self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout) is None:
                ib = k.get("intra_block_utxos") or {}
                if (tx_in.prev_txid, tx_in.prev_vout) not in ib:
                    return False, "bad-txns-inputs-missingorspent"
        mtp = a[0] if a else k.get("block_mtp", 0)
        if not self._is_final_tx(tx, height, mtp):
            return False, "non-final"
        if not self.check_sequence_locks(
            tx, height, mtp, network="regtest",
            intra_block_utxos=k.get("intra_block_utxos"),
        ):
            return False, "non-BIP68-final"
        return True, ""


def _tx(prevouts, value: int, tag: int, *, version: int = 2, locktime: int = 0,
        sequence: int = SEQ_FINAL_RBF) -> Transaction:
    tx = Transaction(
        txid=bytes(32), version=version, locktime=locktime,
        inputs=[TxIn(prev_txid=p, prev_vout=v, script_sig=b"\x51" + bytes([tag]),
                     sequence=sequence) for p, v in prevouts],
        outputs=[TxOut(value=value, script_pubkey=b"\x51")],
    )
    tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
    return tx


def _coinbase(tag: int) -> Transaction:
    cb = Transaction(
        txid=bytes(32), version=1, locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x01" + bytes([tag]), sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=50, script_pubkey=b"\x51")],
    )
    cb.txid = hashlib.sha256(hashlib.sha256(cb.serialize()).digest()).digest()
    return cb


def _ids(mp: Mempool) -> set[bytes]:
    return set(mp.transactions)


# --------------------------------------------------------------------------
# (c)/(e): P2P / submitblock reorg whose new branch double-spends block tx A1
# --------------------------------------------------------------------------

def _reorg_server(mempool, active_blocks: dict, branch_len: int, monkeypatch):
    anc = b"\xa0" + b"\x00" * 31
    side = {}
    prev = anc
    for i in range(branch_len):
        h = bytes([0xb1 + i]) + b"\x00" * 31
        side[h] = (prev, 111 + i, b"\x01")
        prev = h
    new_tip = prev
    db = MagicMock()
    db.get_block_by_height.side_effect = lambda h: active_blocks.get(h)
    best = {"n": 0}

    def _best():
        best["n"] += 1
        if best["n"] == 1:
            return (b"\xff" * 32, max(active_blocks))
        return (new_tip, 110 + branch_len)

    db.get_best_block.side_effect = _best
    db.disconnect_blocks_atomic.side_effect = lambda t, a: [b"\x00" * 32] * (t - a)
    db.connect_blocks_atomic.side_effect = lambda blocks, net: [b"\x00" * 32] * len(blocks)
    db.validate_block_from_bytes.return_value = None
    db.get_block_hash_by_height.side_effect = lambda h: anc if h == 110 else None
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(mempool=mempool, db=db)
    server._side_branch_blocks = side
    server._side_branch_max_entries = 1024
    server._resolve_parent_height = lambda _db, p: 110 if p == anc else None

    async def _fake_accept(*a, **k):
        return b"\x00" * 32

    monkeypatch.setattr(rpc_module, "accept_block", _fake_accept)
    return server, db, new_tip


def test_reorg_failed_readd_removes_in_pool_child(monkeypatch):
    """A1 (block 111) is double-spent by X on the new branch: A1 cannot come
    back, so its in-pool child M2 (spending A1:0) must leave too — Core
    removeRecursive(A1, REORG).  Deployed kept M2 -> invalid template."""
    sdb = _StubDB(tip=112)
    a1 = _tx([COIN1], 99_000_000, 1)
    sdb.utxos[(a1.get_txid(), 0)] = _coin(111)          # A1 confirmed at 111
    sdb.utxos[COIN_O] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    m2 = _tx([(a1.get_txid(), 0)], 98_000_000, 2)
    m1 = _tx([COIN_O], 99_000_000, 3)                    # bystander
    for t in (m2, m1):
        ok, err = mp.add_transaction(t, height=112)
        assert ok, err

    # The reorg: blocks 111..112 disconnected (A1's output gone), the new
    # branch spent COIN1 via X (so COIN1 is not in the chain view either).
    del sdb.utxos[(a1.get_txid(), 0)]
    sdb.tip = 113
    active = {111: SimpleNamespace(transactions=[_coinbase(1), a1]),
              112: SimpleNamespace(transactions=[_coinbase(2)])}
    server, _db, new_tip = _reorg_server(mp, active, 3, monkeypatch)
    assert asyncio.run(server._reorg_to_side_branch_tip(_db, new_tip)) is None

    names = {a1.get_txid(): "A1", m2.get_txid(): "M2", m1.get_txid(): "M1"}
    got = sorted(names.get(t, t.hex()[:8]) for t in _ids(mp))
    assert got == ["M1"], (
        f"after the reorg the pool holds {got}; Core holds [M1]: A1 is "
        f"double-spent by the new branch and its child M2 must be "
        f"removeRecursive'd (an in-pool M2 is an invalid template)")
    assert not mp.orphan_pool.has(a1.get_txid()), \
        "reorg refill must not park a disconnected tx in the orphan pool"
    tmpl, _ = mp.get_block_template_txs()
    assert {t.get_txid() for t in tmpl} == {m1.get_txid()}


def test_reorg_refill_is_earliest_first(monkeypatch):
    """Disconnected txs go back lowest block first, so a child confirmed one
    block above its parent is re-accepted after the parent (not orphaned)."""
    sdb = _StubDB(tip=112)
    sdb.utxos[COIN_O] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    p = _tx([COIN_O], 99_000_000, 4)
    c = _tx([(p.get_txid(), 0)], 98_000_000, 5)
    # p confirmed at 111 and spent by c at 112: after disconnecting both, the
    # chain view has COIN_O unspent and neither output.
    sdb.tip = 113
    active = {111: SimpleNamespace(transactions=[_coinbase(1), p]),
              112: SimpleNamespace(transactions=[_coinbase(2), c])}
    server, _db, new_tip = _reorg_server(mp, active, 3, monkeypatch)
    assert asyncio.run(server._reorg_to_side_branch_tip(_db, new_tip)) is None
    assert _ids(mp) == {p.get_txid(), c.get_txid()}
    assert mp.transactions[c.get_txid()].parents == {p.get_txid()}


# --------------------------------------------------------------------------
# invalidateblock: removeForReorg over EVERY entry, not only re-added ones
# --------------------------------------------------------------------------

def _invalidate_refill(mp, sdb, blocks, new_tip: int) -> None:
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(mempool=mp, db=sdb)
    sdb.tip = new_tip
    asyncio.run(server._update_mempool_after_disconnect(sdb, blocks))


def test_invalidate_drops_in_pool_tx_non_final_at_new_tip():
    """LT (nLockTime 111) entered the pool at tip 111 (final in block 112).
    invalidateblock -> tip 110: LT is non-final for block 111, so Core's
    removeForReorg drops it and its child, though neither was disconnected."""
    sdb = _StubDB(tip=111)
    sdb.utxos[COIN_L] = _coin(5)
    sdb.utxos[COIN_O] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    lt = _tx([COIN_L], 99_000_000, 6, locktime=111)
    lt_child = _tx([(lt.get_txid(), 0)], 98_000_000, 7)
    ok_tx = _tx([COIN_O], 99_000_000, 8)
    for t in (lt, lt_child, ok_tx):
        ok, err = mp.add_transaction(t, height=111)
        assert ok, err
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1)])], 110)
    assert _ids(mp) == {ok_tx.get_txid()}, (
        "LT is non-final at tip+1=111 after the invalidate; it and its "
        "descendant must leave (Core removeForReorg / CheckFinalTxAtTip)")


def test_invalidate_drops_in_pool_tx_bip68_locked_at_new_tip():
    """S (v2, nSequence = 5 blocks) spends a coin confirmed at 105.  At tip
    109 it is valid for block 110 (110-105 = 5 >= 5).  invalidateblock -> tip
    108: for block 109, 109-105 = 4 < 5 -> sequence-locked -> dropped."""
    sdb = _StubDB(tip=109)
    sdb.utxos[COIN_S] = _coin(105)
    mp = Mempool(_Validator(sdb), require_standard=False)
    s = _tx([COIN_S], 99_000_000, 9, sequence=5)
    ok, err = mp.add_transaction(s, height=109)
    assert ok, err
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1)])], 108)
    assert _ids(mp) == set(), (
        "S is BIP68-locked at tip+1=109 after the invalidate; Core "
        "removeForReorg / CheckSequenceLocksAtTip drops it")


def test_invalidate_drops_in_pool_spend_of_now_immature_coinbase():
    """Control for the pre-existing check: a spend of a coinbase that is
    mature at the old tip but immature at the new one leaves."""
    sdb = _StubDB(tip=111)
    sdb.utxos[COIN1] = _coin(12, coinbase=True)
    mp = Mempool(_Validator(sdb), require_standard=False)
    imm = _tx([COIN1], 99_000_000, 10)
    ok, err = mp.add_transaction(imm, height=111)
    assert ok, err
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1)])], 110)
    assert _ids(mp) == set()


def test_invalidate_readded_parent_links_existing_child():
    """invalidateblock 111 re-adds A1; M2 (spending A1:0) is already in the
    pool.  Core UpdateTransactionsFromBlock wires the link, so a later block
    double-spending A1 removes M2 with it (deployed: M2 survived, unlinked)."""
    sdb = _StubDB(tip=111)
    sdb.utxos[COIN1] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    a1 = _tx([COIN1], 99_000_000, 11)
    sdb.utxos[(a1.get_txid(), 0)] = _coin(111)
    del sdb.utxos[COIN1]                                  # A1 confirmed at 111
    m2 = _tx([(a1.get_txid(), 0)], 98_000_000, 12)
    ok, err = mp.add_transaction(m2, height=111)
    assert ok, err
    # invalidateblock 111: A1's output leaves the chain, COIN1 is unspent again.
    del sdb.utxos[(a1.get_txid(), 0)]
    sdb.utxos[COIN1] = _coin(5)
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1), a1])], 110)
    assert _ids(mp) == {a1.get_txid(), m2.get_txid()}
    assert m2.get_txid() in mp.transactions[a1.get_txid()].children
    assert a1.get_txid() in mp.transactions[m2.get_txid()].parents
    assert mp.transactions[m2.get_txid()].ancestor_count == 2
    assert mp.transactions[a1.get_txid()].descendant_count == 2
    # Template order: parent before child.
    tmpl, _ = mp.get_block_template_txs()
    order = [t.get_txid() for t in tmpl]
    assert order.index(a1.get_txid()) < order.index(m2.get_txid())
    # A block confirming X (double-spend of COIN1) removes A1 AND M2.
    x = _tx([COIN1], 97_000_000, 13)
    del sdb.utxos[COIN1]
    mp.remove_block_transactions(SimpleNamespace(transactions=[_coinbase(2), x]))
    assert _ids(mp) == set(), "M2 must go with its conflicted parent A1"


# --------------------------------------------------------------------------
# OU-3: removeForBlock recounts only the affected entries, same result
# --------------------------------------------------------------------------

def test_remove_block_incremental_recount_matches_full_recount():
    sdb = _StubDB(tip=200)
    roots = [(bytes([0xd0 + i]) * 32, 0) for i in range(4)]
    for r in roots:
        sdb.utxos[r] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False, full_rbf=True)
    # chains r0 -> a -> b -> c, r1 -> d -> e, plus a 2-input child of b and d
    a = _tx([roots[0]], 99_000_000, 20)
    b = _tx([(a.get_txid(), 0)], 98_000_000, 21)
    c = _tx([(b.get_txid(), 0)], 97_000_000, 22)
    d = _tx([roots[1]], 99_000_000, 23)
    e = _tx([(d.get_txid(), 0)], 98_000_000, 24)
    f = _tx([roots[2]], 99_000_000, 25)
    for t in (a, b, c, d, e, f):
        ok, err = mp.add_transaction(t, height=200)
        assert ok, err
    # Block confirms a (c and b keep), and a conflicting spend of roots[1]
    # (d, e go as conflicts).
    d_conf = _tx([roots[1]], 90_000_000, 26)
    del sdb.utxos[roots[0]]
    del sdb.utxos[roots[1]]
    sdb.utxos[(a.get_txid(), 0)] = _coin(201)
    mp.remove_block_transactions(SimpleNamespace(transactions=[_coinbase(3), a, d_conf]))
    assert _ids(mp) == {b.get_txid(), c.get_txid(), f.get_txid()}
    for txid, entry in mp.transactions.items():
        anc = mp._get_ancestors(entry.tx)
        desc = mp._collect_descendants(txid) - {txid}
        assert entry.ancestor_count == len(anc) + 1, txid.hex()[:8]
        assert entry.descendant_count == len(desc) + 1, txid.hex()[:8]
        assert entry.ancestor_size == entry.size + sum(mp.transactions[x].size for x in anc)
        assert entry.descendant_size == entry.size + sum(mp.transactions[x].size for x in desc)


def test_reorg_reconfirmed_tx_keeps_its_in_pool_spender(monkeypatch):
    """CONTROL: P is confirmed on BOTH branches (old 111, new 112b).  Its
    re-add fails (already in the chain), but its in-pool spender Q is valid
    — Core never re-offers P (ConnectTip pulled it from the disconnect pool),
    so Q must stay."""
    sdb = _StubDB(tip=112)
    p = _tx([COIN_O], 99_000_000, 30)
    sdb.utxos[(p.get_txid(), 0)] = _coin(111)
    mp = Mempool(_Validator(sdb), require_standard=False)
    q = _tx([(p.get_txid(), 0)], 98_000_000, 31)
    ok, err = mp.add_transaction(q, height=112)
    assert ok, err
    sdb.utxos[(p.get_txid(), 0)] = _coin(112)  # re-confirmed by the new branch
    sdb.tip = 113
    active = {111: SimpleNamespace(transactions=[_coinbase(1), p]),
              112: SimpleNamespace(transactions=[_coinbase(2)])}
    server, _db, new_tip = _reorg_server(mp, active, 3, monkeypatch)
    assert asyncio.run(server._reorg_to_side_branch_tip(_db, new_tip)) is None
    assert _ids(mp) == {q.get_txid()}


def test_reconsider_branch_switch_follows_rust_reorg():
    """reconsiderblock whose ActivateBestChain SWITCHES branches (the old tip
    111' is disconnected, 111..112 connected): Core returns 111''s txs to the
    pool (MaybeUpdateMempoolForReorg) and removeForBlock's the connected
    blocks.  Deployed only handled the pure height-increase case and lost
    111''s txs."""
    from ouroboros.database import Block

    def _blk(prev: bytes, txs, nonce: int) -> Block:
        b = Block(version=4, prev_blockhash=prev, merkle_root=b"\x00" * 32,
                  timestamp=1_700_000_000 + nonce, bits=0x207FFFFF, nonce=nonce,
                  transactions=txs, hash=b"")
        b.hash = hashlib.sha256(hashlib.sha256(b.serialize()[:80]).digest()).digest()
        return b

    sdb = _StubDB(tip=111)
    sdb.utxos[COIN_O] = _coin(5)
    sdb.utxos[COIN1] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    anc = b"\xa0" * 32
    w = _tx([COIN_O], 99_000_000, 40)          # confirmed in the losing 111'
    y = _tx([COIN1], 99_000_000, 41)           # confirmed in the winning 112
    old = _blk(anc, [_coinbase(40), w], 1)
    new1 = _blk(anc, [_coinbase(41)], 2)
    new2 = _blk(new1.hash, [_coinbase(42), y], 3)
    raws = {old.hash: old.serialize()}
    # mempool before: y is in the pool (it was unconfirmed on the old branch)
    ok, err = mp.add_transaction(y, height=111)
    assert ok, err
    # Rust reorg done: tip 112 on the new branch; COIN1 spent by y in 112.
    del sdb.utxos[COIN1]
    sdb.tip = 112
    active = {110: anc, 111: new1.hash, 112: new2.hash}
    by_h = {111: new1, 112: new2}
    db = SimpleNamespace(
        get_best_block=lambda: (new2.hash, 112),
        get_block_hash_by_height=lambda h: active.get(h),
        get_block_bytes=lambda h: raws.get(bytes(h)),
        get_block_by_height=lambda h: by_h.get(h),
    )
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(mempool=mp, db=db)
    server._mempool_follow_rust_reorg(db, old.hash, 111)
    assert _ids(mp) == {w.get_txid()}, (
        "after the branch switch: y confirmed (removeForBlock), w back in "
        "the pool (its block 111' was disconnected)")


# --------------------------------------------------------------------------
# Warden #124 review, point 1: cluster limits after the re-added parent is
# linked (Core UpdateTransactionsFromBlock -> m_txgraph->Trim() ->
# removeUnchecked(SIZELIMIT)), and the byte cap after the link.
# --------------------------------------------------------------------------

def _fan_tx(prevout, n_out: int, out_value: int, tag: int,
            spk: bytes = b"\x51") -> Transaction:
    tx = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=prevout[0], prev_vout=prevout[1],
                     script_sig=b"\x51" + bytes([tag & 0xFF, tag >> 8]),
                     sequence=SEQ_FINAL_RBF)],
        outputs=[TxOut(value=out_value, script_pubkey=spk) for _ in range(n_out)],
    )
    tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
    return tx


def _confirmed_parent_with_children(n_children: int, child_fee, spk=b"\x51"):
    """P (confirmed at 111) fans out to *n_children* outputs; child i, in the
    pool, spends P:i paying child_fee(i)."""
    sdb = _StubDB(tip=111)
    p = _fan_tx(COIN_O, n_children, 1_000_000, 0x700)
    for i in range(n_children):
        sdb.utxos[(p.get_txid(), i)] = _coin(111)
    mp = Mempool(_Validator(sdb), require_standard=False)
    kids = []
    for i in range(n_children):
        c = _fan_tx((p.get_txid(), i), 1, 1_000_000 - child_fee(i), 0x800 + i, spk)
        ok, err = mp.add_transaction(c, height=111)
        assert ok, err
        kids.append(c)
    # invalidateblock 111: P's outputs leave the chain, COIN_O is unspent.
    for i in range(n_children):
        del sdb.utxos[(p.get_txid(), i)]
    sdb.utxos[COIN_O] = _coin(5)
    return sdb, mp, p, kids


def _assert_clusters_within_limits(mp: Mempool) -> None:
    from ouroboros.mempool import MAX_CLUSTER_COUNT, MAX_CLUSTER_SIZE_WEIGHT
    mp._cluster_manager.rebuild()
    for cl in mp._cluster_manager.get_all_clusters():
        assert cl.size() <= MAX_CLUSTER_COUNT
        assert sum(mp.transactions[t].sigop_adjusted_weight
                   for t in cl.txids) <= MAX_CLUSTER_SIZE_WEIGHT


def test_reorg_readded_parent_trims_65_tx_cluster():
    """P comes back from a disconnected block onto 64 in-pool children: a
    65-tx cluster.  ATMP's cluster gate ran before the children were linked,
    so it passed.  Core Trim keeps P (no unmet dependency) and the 63
    best-feerate children, and drops the lowest-feerate child (SIZELIMIT)."""
    sdb, mp, p, kids = _confirmed_parent_with_children(
        64, lambda i: 2_000 + 10 * i)          # kid 0 pays least
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1), p])], 110)
    assert p.get_txid() in mp.transactions, "P must be re-added"
    assert len(mp.transactions) == 64, (
        f"pool holds {len(mp.transactions)} txs in one cluster; Core trims "
        f"the 65-tx cluster to 64")
    assert kids[0].get_txid() not in mp.transactions, \
        "the lowest-feerate child is the one Core's Trim drops"
    assert all(k.get_txid() in mp.transactions for k in kids[1:])
    assert mp.transactions[p.get_txid()].descendant_count == 64
    _assert_clusters_within_limits(mp)


def test_reorg_readded_parent_trims_cluster_over_weight_limit():
    """Same hole on the size limit: 10 children of ~41.8k weight each plus P
    exceed 404,000 weight.  The lowest-feerate child goes."""
    big = b"\x6a" + b"\x00" * 10_400               # ~10.45 kvB per child
    sdb, mp, p, kids = _confirmed_parent_with_children(
        10, lambda i: 20_000 + 100 * i, spk=big)
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1), p])], 110)
    assert p.get_txid() in mp.transactions
    assert kids[0].get_txid() not in mp.transactions
    assert all(k.get_txid() in mp.transactions for k in kids[1:])
    _assert_clusters_within_limits(mp)


def test_reorg_size_limit_evicts_readded_parent_with_its_in_pool_child():
    """After the reorg the pool is over its byte cap.  P (re-added, lowest
    feerate) and its in-pool child C form one chunk once linked, so the
    size-limit eviction takes them together; the bystander B stays.  An
    unlinked P would be evicted alone and leave C spending a coin that
    exists nowhere."""
    sdb = _StubDB(tip=111)
    p = _tx([COIN1], 100_000_000 - 300, 50)        # ~1 sat/B
    sdb.utxos[(p.get_txid(), 0)] = _coin(111)
    sdb.utxos[COIN_O] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    c = _tx([(p.get_txid(), 0)], 100_000_000 - 300 - 2_000, 51)
    b = _tx([COIN_O], 100_000_000 - 50_000, 52)
    for t in (c, b):
        ok, err = mp.add_transaction(t, height=111)
        assert ok, err
    del sdb.utxos[(p.get_txid(), 0)]
    sdb.utxos[COIN1] = _coin(5)
    mp.max_size = mp.current_size + mp.transactions[c.get_txid()].size - 1
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1), p])], 110)
    assert _ids(mp) == {b.get_txid()}, (
        "the byte cap must evict the low-feerate parent together with its "
        "in-pool child; the bystander stays")


# --------------------------------------------------------------------------
# Warden #124 review, point 2: BlockSync._handle_reorg (the P2P orphan path)
# refills through update_for_reorg, not one add_transaction per tx.
# --------------------------------------------------------------------------

def _p2p_reorg(old_tip_txs, new_tip_txs, mp):
    from tests.test_w121_compact_filters import _build_fix74_harness
    sync, _idx, _a0, a1, b1 = _build_fix74_harness()
    a1.transactions = [_coinbase(60)] + old_tip_txs
    b1.transactions = [_coinbase(61)] + new_tip_txs
    sync.mempool = mp
    assert asyncio.run(sync._handle_reorg(b1, b1.hash)) is True


def test_p2p_reorg_failed_readd_removes_in_pool_child():
    """A1 (old tip) is double-spent by X in the new tip: A1 cannot return,
    so its in-pool child M2 leaves with it; bystander M1 stays.  The old
    per-tx add_transaction refill kept M2 (and parked A1 as an orphan)."""
    sdb = _StubDB(tip=1)
    a1 = _tx([COIN1], 99_000_000, 62)
    sdb.utxos[(a1.get_txid(), 0)] = _coin(1)
    sdb.utxos[COIN_O] = _coin(0)
    mp = Mempool(_Validator(sdb), require_standard=False)
    m2 = _tx([(a1.get_txid(), 0)], 98_000_000, 63)
    m1 = _tx([COIN_O], 99_000_000, 64)
    for t in (m2, m1):
        ok, err = mp.add_transaction(t, height=1)
        assert ok, err
    x = _tx([COIN1], 97_000_000, 65)
    del sdb.utxos[(a1.get_txid(), 0)]               # COIN1 spent by X now
    _p2p_reorg([a1], [x], mp)
    assert _ids(mp) == {m1.get_txid()}
    assert not mp.orphan_pool.has(a1.get_txid())


def test_p2p_reorg_readded_parent_links_in_pool_child():
    """A1 returns (the new tip does not touch COIN1): it is linked to its
    in-pool child M2, so the template orders A1 before M2."""
    sdb = _StubDB(tip=1)
    a1 = _tx([COIN1], 99_000_000, 66)
    sdb.utxos[(a1.get_txid(), 0)] = _coin(1)
    mp = Mempool(_Validator(sdb), require_standard=False)
    m2 = _tx([(a1.get_txid(), 0)], 98_000_000, 67)
    ok, err = mp.add_transaction(m2, height=1)
    assert ok, err
    del sdb.utxos[(a1.get_txid(), 0)]
    sdb.utxos[COIN1] = _coin(0)
    _p2p_reorg([a1], [], mp)
    assert _ids(mp) == {a1.get_txid(), m2.get_txid()}
    assert mp.transactions[m2.get_txid()].parents == {a1.get_txid()}
    order = [t.get_txid() for t in mp.get_block_template_txs()[0]]
    assert order.index(a1.get_txid()) < order.index(m2.get_txid())


# --------------------------------------------------------------------------
# Warden #124 review, point 3: invalidateblock re-adds only the 10 highest
# disconnected blocks; an unavailable MTP and a missing ancestor header fail
# closed in removeForReorg.
# --------------------------------------------------------------------------

def test_deep_invalidate_readds_only_top_ten_blocks():
    """12 blocks disconnected, each confirming t_i.  Core re-adds while
    ++disconnected <= 10, tip first: t_3..t_12 come back, t_1/t_2 do not,
    and M (in the pool, spending t_1:0) leaves by removeRecursive."""
    sdb = _StubDB(tip=112)
    coins = [(bytes([0x90 + i]) * 32, 0) for i in range(12)]
    txs = [_tx([coins[i]], 99_000_000, 70 + i) for i in range(12)]
    for t in txs:
        sdb.utxos[(t.get_txid(), 0)] = _coin(101)
    mp = Mempool(_Validator(sdb), require_standard=False)
    m = _tx([(txs[0].get_txid(), 0)], 98_000_000, 90)
    ok, err = mp.add_transaction(m, height=112)
    assert ok, err
    for i, t in enumerate(txs):
        del sdb.utxos[(t.get_txid(), 0)]
        sdb.utxos[coins[i]] = _coin(5)
    blocks = [SimpleNamespace(transactions=[_coinbase(100 + i), t])
              for i, t in enumerate(txs)]                    # ascending
    _invalidate_refill(mp, sdb, blocks, 100)
    assert _ids(mp) == {t.get_txid() for t in txs[2:]}, (
        "only the 10 highest disconnected blocks are re-added; the in-pool "
        "spender of a not-re-added tx goes")


class _MtpDownDB(_StubDB):
    down = False

    def get_median_time_past(self, height: int):
        if self.down:
            raise KeyError("block index row missing")
        return super().get_median_time_past(height)


def test_remove_for_reorg_fails_closed_without_tip_mtp():
    """If the new tip's MTP cannot be read, nLockTime / BIP68 cannot be
    judged.  LT (non-final at the new tip) and S (sequence-locked there)
    must not survive on a skipped check; the unconstrained tx stays."""
    sdb = _MtpDownDB(tip=111)
    sdb.utxos[COIN_L] = _coin(5)
    sdb.utxos[COIN_S] = _coin(107)
    sdb.utxos[COIN_O] = _coin(5)
    mp = Mempool(_Validator(sdb), require_standard=False)
    lt = _tx([COIN_L], 99_000_000, 91, locktime=111)
    s = _tx([COIN_S], 99_000_000, 92, sequence=5)
    plain = _tx([COIN_O], 99_000_000, 93)
    for t in (lt, s, plain):
        ok, err = mp.add_transaction(t, height=111)
        assert ok, err
    sdb.down = True
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1)])], 110)
    assert _ids(mp) == {plain.get_txid()}


def test_remove_for_reorg_fails_closed_on_missing_ancestor_header():
    """BIP68 for S needs an ancestor header below the header floor
    (MissingAncestorHeaderError).  ATMP refuses such a tx; removeForReorg
    drops it rather than keep an unverified relative lock."""
    from ouroboros.validation import MissingAncestorHeaderError

    class _NoHeaderValidator(_Validator):
        missing = None   # txid whose relative lock is unverifiable

        def check_sequence_locks(self, tx, *a, **k):
            if tx.get_txid() == self.missing:
                raise MissingAncestorHeaderError("below the header floor")
            return super().check_sequence_locks(tx, *a, **k)

    sdb = _StubDB(tip=111)
    sdb.utxos[COIN_S] = _coin(100)
    sdb.utxos[COIN_O] = _coin(5)
    v = _NoHeaderValidator(sdb)
    mp = Mempool(v, require_standard=False)
    s = _tx([COIN_S], 99_000_000, 94, sequence=5)
    plain = _tx([COIN_O], 99_000_000, 95)
    for t in (s, plain):
        ok, err = mp.add_transaction(t, height=111)
        assert ok, err
    v.missing = s.get_txid()
    _invalidate_refill(mp, sdb, [SimpleNamespace(transactions=[_coinbase(1)])], 110)
    assert _ids(mp) == {plain.get_txid()}
