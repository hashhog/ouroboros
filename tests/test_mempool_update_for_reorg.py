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
