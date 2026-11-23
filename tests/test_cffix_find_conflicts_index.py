"""cffix-ouroboros-find-conflicts-index: _find_conflicts must use the spend index.

``Mempool._find_conflicts`` is the first step of every RBF attempt
(``_try_replace_inner``).  It used to walk every mempool entry's inputs once
per conflicting input, so a double-spend with k conflicting inputs against an
n-entry pool cost O(k * n * inputs) before any RBF rule ran.

Bitcoin Core answers the same question from ``mapNextTx``: PreChecks calls
``m_pool.GetConflictTx(txin.prevout)`` per input (src/validation.cpp), a
single indexed lookup (src/txmempool.cpp).  ouroboros already keeps that
index as ``spender_by_outpoint``; these tests pin that _find_conflicts reads
it instead of scanning ``self.transactions``.
"""

import time

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool, MempoolEntry

POOL_SIZE = 2_000
N_CONFLICTS = 10


def _txid(tag: int) -> bytes:
    return tag.to_bytes(4, "little") + b"\xab" * 28


def _make_tx(txid: bytes, inputs, n_out: int = 1) -> Transaction:
    return Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=[
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=b"", sequence=0xFFFFFFFD)
            for pt, pv in inputs
        ],
        outputs=[TxOut(value=1_000, script_pubkey=b"\x51") for _ in range(n_out)],
    )


class _CountingDict(dict):
    """dict whose whole-map iterations are counted.

    Point lookups (``get``, ``[]``, ``in``) are not counted: those are what an
    indexed conflict lookup is expected to do.
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.full_iterations = 0

    def items(self):
        self.full_iterations += 1
        return super().items()

    def values(self):
        self.full_iterations += 1
        return super().values()

    def keys(self):
        self.full_iterations += 1
        return super().keys()

    def __iter__(self):
        self.full_iterations += 1
        return super().__iter__()


def _insert(pool: Mempool, tx: Transaction) -> None:
    """Insert an entry the way add_transaction does for the spend indexes.

    Keeps ``spent_outputs`` and ``spender_by_outpoint`` in lock-step, which is
    the invariant every production insert site maintains.
    """
    txid = tx.get_txid()
    size = len(tx.serialize())
    pool.transactions[txid] = MempoolEntry(
        tx=tx, fee=1_000, fee_rate=1_000 / size, size=size,
        time_added=time.time(), height_added=100,
    )
    for inp in tx.inputs:
        op = (inp.prev_txid, inp.prev_vout)
        pool.spent_outputs.add(op)
        pool.spender_by_outpoint[op] = txid


def _reference_conflicts(pool: Mempool, tx: Transaction) -> set[bytes]:
    """The old full-scan definition: every pool tx sharing an input with tx."""
    wanted = {(i.prev_txid, i.prev_vout) for i in tx.inputs}
    return {
        txid
        for txid, entry in dict.items(pool.transactions)
        for i in entry.tx.inputs
        if (i.prev_txid, i.prev_vout) in wanted
    }


def _populated_pool():
    pool = Mempool(validator=None, require_standard=False)
    coins = []
    for n in range(POOL_SIZE):
        coin = _txid(1_000_000 + n)
        coins.append(coin)
        # Two inputs per entry so a matching outpoint is not always input 0.
        _insert(pool, _make_tx(_txid(n), [(_txid(5_000_000 + n), 3), (coin, 0)]))
    return pool, coins


def test_find_conflicts_uses_spend_index_not_full_scan():
    pool, coins = _populated_pool()
    # A 10-input double-spend: each input conflicts with a different entry.
    picks = [0, 1, 7, 100, 555, 999, 1_234, 1_500, 1_998, 1_999]
    assert len(picks) == N_CONFLICTS
    ds = _make_tx(_txid(9_999_999), [(coins[p], 0) for p in picks])

    expected = _reference_conflicts(pool, ds)
    assert expected == {_txid(p) for p in picks}

    counting = _CountingDict(pool.transactions)
    pool.transactions = counting

    got = pool._find_conflicts(ds)

    assert counting.full_iterations == 0, (
        f"_find_conflicts iterated the whole mempool {counting.full_iterations} "
        f"times for a {N_CONFLICTS}-input double-spend; Core's GetConflictTx "
        f"is an indexed lookup per input"
    )
    assert got == expected


def test_find_conflicts_dedups_two_inputs_hitting_one_entry():
    """Two inputs of the replacement spending both inputs of ONE pool entry
    yield that entry once."""
    pool, coins = _populated_pool()
    ds = _make_tx(_txid(9_999_998), [(coins[42], 0), (_txid(5_000_042), 3)])
    pool.transactions = _CountingDict(pool.transactions)
    got = pool._find_conflicts(ds)
    assert pool.transactions.full_iterations == 0
    assert got == {_txid(42)} == _reference_conflicts(pool, ds)


def test_find_conflicts_none_for_non_conflicting_tx():
    """Negative control: unspent-in-pool outpoints and an in-pool parent's
    unspent output are not conflicts."""
    pool, _ = _populated_pool()
    # Spends output 1 of pool tx 3 (pool tx 3 has one output, but the point is
    # that nothing in the pool spends (txid(3), 1)) and a fresh coin.
    tx = _make_tx(_txid(9_999_997), [(_txid(3), 1), (_txid(8_888_888), 0)])
    pool.transactions = _CountingDict(pool.transactions)
    assert pool._find_conflicts(tx) == set() == _reference_conflicts(pool, tx)
    assert pool.transactions.full_iterations == 0


def test_find_conflicts_after_real_replacement_and_removal():
    """The index stays exact across remove_transaction: a removed entry's
    outpoints are no longer reported as conflicts."""
    pool, coins = _populated_pool()
    pool.remove_transaction(_txid(10))
    ds = _make_tx(_txid(9_999_996), [(coins[10], 0), (coins[11], 0)])
    assert pool._find_conflicts(ds) == {_txid(11)} == _reference_conflicts(pool, ds)
