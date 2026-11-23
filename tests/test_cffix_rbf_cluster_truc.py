"""A replacement goes through the same TRUC and cluster gates as any other tx.

``_add_transaction_inner`` handed every conflicting transaction to
``_try_replace_inner`` and returned its verdict before ``_check_truc_policy``
and ``_check_cluster_limit`` ran.  ``_try_replace_inner`` only re-checked the
TRUC ancestor count and the 10,000 vB TRUC cap, so a replacement could:

* merge up to 100 clusters into one far past the 64-tx cluster limit (the
  merged cluster then feeds the superlinear ``ClusterLinearizer``);
* be a 5,000 vB v3 child of a v3 parent (TRUC child cap is 1,000 vB);
* be a non-v3 child of a v3 parent (TRUC inheritance).

Bitcoin Core runs ``SingleTRUCChecks(..., ws.m_conflicts, ...)`` in PreChecks
for every tx, replacements included (validation.cpp:956), and
``ReplacementChecks`` runs ``m_changeset->CheckMemPoolPolicyLimits()`` on the
post-replacement graph and rejects with "too-large-cluster" (validation.cpp:
1023-1024), before the feerate-diagram check.

The controls pin the other side: evicted transactions do not count toward the
merged cluster, and a TRUC child that fits the rules still replaces its sibling.
"""

from __future__ import annotations

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import CLUSTER_REJECT_TOKEN, MAX_CLUSTER_COUNT, Mempool

HEIGHT = 200
COIN_VALUE = 100_000_000
CHAIN_FEE = 1_000
SEQ = 0xFFFFFFFD


def _txid(tag: int) -> bytes:
    return tag.to_bytes(4, "big") + b"\xab" * 28


class _StubDB:
    def __init__(self, utxos: dict):
        self._u = utxos

    def get_utxo(self, txid: bytes, vout: int):
        return self._u.get((txid, vout))

    def get_block_height(self):
        return HEIGHT

    def get_median_time_past(self, height: int | None = None) -> int:
        return 1_600_000_000


class _StubValidator:
    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, *a, **kw):
        return True, ""


def _pool(n_coins: int) -> tuple[Mempool, list[bytes]]:
    coins = [_txid(0x0F000000 + i) for i in range(n_coins)]
    utxos = {
        (c, 0): {"value": COIN_VALUE, "script_pubkey": b"\x51", "height": 1,
                 "is_coinbase": False}
        for c in coins
    }
    pool = Mempool(validator=_StubValidator(utxos), require_standard=False,
                   full_rbf=True)
    return pool, coins


def _tx(tag: int, inputs: list[tuple[bytes, int]], out_value: int,
        version: int = 2, pad: int = 0) -> Transaction:
    """One-output tx; *pad* extra bytes in the output script inflate vsize."""
    return Transaction(
        txid=_txid(tag),
        version=version,
        locktime=0,
        inputs=[TxIn(prev_txid=t, prev_vout=v, script_sig=b"", sequence=SEQ)
                for t, v in inputs],
        outputs=[TxOut(value=out_value, script_pubkey=b"\x51" + b"\x00" * pad)],
    )


def _add(pool: Mempool, tx: Transaction) -> None:
    ok, err = pool.add_transaction(tx, HEIGHT)
    assert ok, f"setup tx {tx.get_txid().hex()[:8]} rejected: {err}"


def _chain(pool: Mempool, coin: bytes, tag0: int, length: int) -> Transaction:
    """Add a *length*-tx chain spending *coin*; return its tip."""
    prev, value = (coin, 0), COIN_VALUE
    tip = None
    for i in range(length):
        value -= CHAIN_FEE
        tip = _tx(tag0 + i, [prev], value)
        _add(pool, tip)
        prev = (tip.get_txid(), 0)
    return tip


def _two_full_clusters(pool: Mempool, coins: list[bytes], length: int):
    """Two clusters, each a *length*-tx chain plus one low-fee leaf child."""
    tip_a = _chain(pool, coins[0], 0x1000, length)
    tip_b = _chain(pool, coins[1], 0x2000, length)
    leaf_a = _tx(0x3001, [(tip_a.get_txid(), 0)], tip_a.outputs[0].value - CHAIN_FEE)
    leaf_b = _tx(0x3002, [(tip_b.get_txid(), 0)], tip_b.outputs[0].value - CHAIN_FEE)
    _add(pool, leaf_a)
    _add(pool, leaf_b)
    return tip_a, tip_b, leaf_a, leaf_b


def _merging_replacement(tip_a: Transaction, tip_b: Transaction) -> Transaction:
    """Spends both tips (conflicting with both leaves) and pays a large fee."""
    value = tip_a.outputs[0].value + tip_b.outputs[0].value - 500_000
    return _tx(0x4000, [(tip_a.get_txid(), 0), (tip_b.get_txid(), 0)], value)


# ---------------------------------------------------------------------------
# (1) cluster limit on the replacement path
# ---------------------------------------------------------------------------

def test_replacement_merging_two_full_clusters_is_too_large_cluster():
    pool, coins = _pool(2)
    tip_a, tip_b, leaf_a, leaf_b = _two_full_clusters(pool, coins, 63)
    assert len(pool.transactions) == 2 * (MAX_CLUSTER_COUNT)

    repl = _merging_replacement(tip_a, tip_b)
    # 63 + 63 + 1 = 127 > 64 after the two leaves are evicted.
    assert pool.add_transaction(repl, HEIGHT) == (False, CLUSTER_REJECT_TOKEN)
    assert repl.get_txid() not in pool.transactions
    assert leaf_a.get_txid() in pool.transactions
    assert leaf_b.get_txid() in pool.transactions


def test_replacement_too_large_cluster_also_in_test_accept():
    pool, coins = _pool(2)
    tip_a, tip_b, _, _ = _two_full_clusters(pool, coins, 63)
    repl = _merging_replacement(tip_a, tip_b)
    with pool._lock:
        got = pool._add_transaction_inner(repl, HEIGHT, test_accept=True)
    assert got == (False, CLUSTER_REJECT_TOKEN)


def test_try_replace_entry_point_enforces_cluster_limit():
    # Wallet bumpfee submits through Mempool.try_replace directly.
    pool, coins = _pool(2)
    tip_a, tip_b, _, _ = _two_full_clusters(pool, coins, 63)
    repl = _merging_replacement(tip_a, tip_b)
    assert pool.try_replace(repl, HEIGHT) == (False, CLUSTER_REJECT_TOKEN)
    assert repl.get_txid() not in pool.transactions


def test_control_evicted_txs_do_not_count_toward_cluster():
    # One 64-tx cluster (63 chain + leaf).  Replacing the leaf keeps the
    # cluster at 64: the evicted leaf must not be counted alongside its
    # replacement.
    pool, coins = _pool(1)
    tip = _chain(pool, coins[0], 0x1000, 63)
    leaf = _tx(0x3001, [(tip.get_txid(), 0)], tip.outputs[0].value - CHAIN_FEE)
    _add(pool, leaf)
    repl = _tx(0x4000, [(tip.get_txid(), 0)], tip.outputs[0].value - 200_000)
    assert pool.add_transaction(repl, HEIGHT) == (True, "")
    assert leaf.get_txid() not in pool.transactions
    assert repl.get_txid() in pool.transactions


def test_control_replacement_merging_two_small_clusters_is_accepted():
    pool, coins = _pool(2)
    tip_a, tip_b, leaf_a, leaf_b = _two_full_clusters(pool, coins, 31)
    repl = _merging_replacement(tip_a, tip_b)
    # 31 + 31 + 1 = 63 <= 64.
    assert pool.add_transaction(repl, HEIGHT) == (True, "")
    assert leaf_a.get_txid() not in pool.transactions
    assert leaf_b.get_txid() not in pool.transactions


# ---------------------------------------------------------------------------
# (2)/(3) TRUC rules on the replacement path
# ---------------------------------------------------------------------------

def _truc_parent_and_child(pool: Mempool, coins: list[bytes]):
    parent = _tx(0x5000, [(coins[0], 0)], COIN_VALUE - CHAIN_FEE, version=3)
    _add(pool, parent)
    # ~200 vB v3 child.
    child = _tx(0x5001, [(parent.get_txid(), 0)],
                parent.outputs[0].value - CHAIN_FEE, version=3, pad=140)
    _add(pool, child)
    return parent, child


def test_oversized_v3_replacement_child_is_rejected():
    pool, coins = _pool(1)
    parent, child = _truc_parent_and_child(pool, coins)
    big = _tx(0x5002, [(parent.get_txid(), 0)],
              parent.outputs[0].value - 1_000_000, version=3, pad=4_940)
    assert 4_900 < big.get_vsize() <= 10_000
    ok, err = pool.add_transaction(big, HEIGHT)
    assert not ok
    assert "child tx is too big" in err, err
    assert big.get_txid() not in pool.transactions
    assert child.get_txid() in pool.transactions


def test_non_v3_replacement_of_v3_child_is_rejected():
    pool, coins = _pool(1)
    parent, child = _truc_parent_and_child(pool, coins)
    v2 = _tx(0x5003, [(parent.get_txid(), 0)],
             parent.outputs[0].value - 100_000, version=2)
    ok, err = pool.add_transaction(v2, HEIGHT)
    assert not ok
    assert "non-version=3 tx cannot spend from version=3 tx" in err, err
    assert v2.get_txid() not in pool.transactions
    assert child.get_txid() in pool.transactions


def test_control_small_v3_replacement_child_is_accepted():
    pool, coins = _pool(1)
    parent, child = _truc_parent_and_child(pool, coins)
    repl = _tx(0x5004, [(parent.get_txid(), 0)],
               parent.outputs[0].value - 100_000, version=3, pad=300)
    assert repl.get_vsize() <= 1_000
    assert pool.add_transaction(repl, HEIGHT) == (True, "")
    assert child.get_txid() not in pool.transactions
    assert repl.get_txid() in pool.transactions


def test_control_v3_replacement_never_leaves_two_children():
    # The parent has two outputs and one child (on output 0).  A v3 tx that
    # spends output 1 AND double-spends an unrelated confirmed coin is a
    # replacement, so it now reaches the TRUC descendant limit, which names
    # the child as a sibling to evict.  Whatever the RBF rules then decide,
    # the parent must not end up with two children.  (Passes on master too:
    # ouroboros's "new unconfirmed input" rule rejects it there; this pins
    # that folding the sibling into the conflicts did not open a way in.)
    pool, coins = _pool(2)
    parent = Transaction(
        txid=_txid(0x6000), version=3, locktime=0,
        inputs=[TxIn(prev_txid=coins[0], prev_vout=0, script_sig=b"", sequence=SEQ)],
        outputs=[TxOut(value=40_000_000, script_pubkey=b"\x51"),
                 TxOut(value=40_000_000, script_pubkey=b"\x51")],
    )
    _add(pool, parent)
    child = _tx(0x6001, [(parent.get_txid(), 0)], 40_000_000 - CHAIN_FEE, version=3)
    _add(pool, child)
    other = _tx(0x6002, [(coins[1], 0)], COIN_VALUE - CHAIN_FEE, version=3)
    _add(pool, other)

    repl = _tx(0x6003, [(parent.get_txid(), 1), (coins[1], 0)],
               40_000_000 + COIN_VALUE - 1_000_000, version=3)
    ok, _ = pool.add_transaction(repl, HEIGHT)
    children = [t for t in (child.get_txid(), repl.get_txid()) if t in pool.transactions]
    assert len(children) == 1, "v3 parent ended up with two children"
    if not ok:
        assert child.get_txid() in pool.transactions
        assert other.get_txid() in pool.transactions
