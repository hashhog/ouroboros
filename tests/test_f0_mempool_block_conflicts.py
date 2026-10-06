"""F0 sweep — the mempool must not keep a spend of a coin the chain spent.

Core ``CTxMemPool::removeForBlock`` (txmempool.cpp) removes each block tx that
is in the pool AND calls ``removeConflicts(tx)``: any pool tx spending an
outpoint the block tx spends is removed with all its descendants
(``removeRecursive(..., CONFLICT)``) and its prioritisation cleared.

Deployed ouroboros (60c3a87) ``remove_block_transactions`` removed only the
block's own txids, so after a block confirmed a DIFFERENT spend of coin C the
pool kept tx T (spending C) and its child — a spend of a coin that is no longer
in the chain's coin view, handed out by getblocktemplate (an invalid block
template) and relayed.  This is the "mempool reads a second coin view" F0
shape: the pool's picture of C stayed pre-spend after the chain spent it.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool

COIN_C = (b"\xc0" * 32, 0)
OTHER = (b"\xd0" * 32, 0)


class _StubDB:
    def __init__(self) -> None:
        self.utxos = {
            COIN_C: {"value": 100_000_000, "script_pubkey": b"\x51", "height": 1,
                     "is_coinbase": False},
            OTHER: {"value": 100_000_000, "script_pubkey": b"\x51", "height": 1,
                    "is_coinbase": False},
        }

    def get_utxo(self, txid: bytes, vout: int):
        return self.utxos.get((txid, vout))


class _OkValidator:
    def __init__(self, db) -> None:
        self.db = db

    def validate_transaction(self, tx, height, *a, **k):
        return True, ""


def _tx(prevouts, value: int, tag: int) -> Transaction:
    tx = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=p, prev_vout=v, script_sig=b"\x51" + bytes([tag]),
                     sequence=0xFFFFFFFD) for p, v in prevouts],
        outputs=[TxOut(value=value, script_pubkey=b"\x51")],
    )
    tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
    return tx


def _coinbase() -> Transaction:
    cb = Transaction(
        txid=bytes(32), version=1, locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x01\x66", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=50, script_pubkey=b"\x51")],
    )
    cb.txid = hashlib.sha256(hashlib.sha256(cb.serialize()).digest()).digest()
    return cb


def _pool_with_t_and_child():
    db = _StubDB()
    mp = Mempool(_OkValidator(db), require_standard=False)
    t = _tx([COIN_C], 99_000_000, 1)
    ok, err = mp.add_transaction(t, height=100)
    assert ok, err
    child = _tx([(t.get_txid(), 0)], 98_000_000, 2)
    ok, err = mp.add_transaction(child, height=100)
    assert ok, err
    bystander = _tx([OTHER], 99_000_000, 3)
    ok, err = mp.add_transaction(bystander, height=100)
    assert ok, err
    return db, mp, t, child, bystander


def test_block_conflict_evicts_pool_spend_and_descendants():
    db, mp, t, child, bystander = _pool_with_t_and_child()
    mp.map_deltas[t.get_txid()] = 5_000  # prioritised — Core clears it
    # The chain confirms T' — a DIFFERENT spend of the same coin C.
    t_prime = _tx([COIN_C], 97_000_000, 9)
    assert t_prime.get_txid() != t.get_txid()
    del db.utxos[COIN_C]  # connect committed: C is spent in the chain view
    mp.remove_block_transactions(SimpleNamespace(transactions=[_coinbase(), t_prime]))

    template, _ = mp.get_block_template_txs()
    tmpl = {tx.get_txid() for tx in template}
    still = [n for n, x in (("T", t), ("child", child)) if x.get_txid() in mp.transactions]
    assert not still, (
        f"after a block spent coin C via T', the pool still holds {still} "
        f"(spending C / its output); getblocktemplate offers "
        f"{[n for n, x in (('T', t), ('child', child)) if x.get_txid() in tmpl]} "
        f"— an invalid template. Core removeForBlock -> removeConflicts")
    assert t.get_txid() not in tmpl and child.get_txid() not in tmpl
    assert COIN_C not in mp.spender_by_outpoint
    assert COIN_C not in mp.spent_outputs
    assert t.get_txid() not in mp.map_deltas  # ClearPrioritisation on CONFLICT
    # CONTROL: an unrelated pool tx survives the block.
    assert bystander.get_txid() in mp.transactions


def test_control_block_including_the_pool_tx_keeps_its_child():
    """CONTROL (passes on deployed too): when the block confirms T itself, T
    leaves the pool and its child STAYS (its parent is now confirmed) — Core
    removeForBlock removes the entry only, not its descendants."""
    db, mp, t, child, bystander = _pool_with_t_and_child()
    mp.remove_block_transactions(SimpleNamespace(transactions=[_coinbase(), t]))
    assert t.get_txid() not in mp.transactions
    assert child.get_txid() in mp.transactions
    assert bystander.get_txid() in mp.transactions
