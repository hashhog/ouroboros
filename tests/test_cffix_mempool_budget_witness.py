"""Witness bytes count against -maxmempool and in eviction feerates.

Security-audit blind pass on ouroboros 721bcd5, record
``ouroboros:mempool:stripped-size-mempool-budget-and-eviction``: the pool
kept its byte budget and its chunk feerates on the STRIPPED (witness-less)
size of each transaction.  A transaction carrying a ~390 KB tapscript witness
then counted ~100 bytes against -maxmempool, and its chunk feerate was its fee
over ~100 bytes, so a witness-heavy, low-feerate transaction outranked an
honest one and the honest one was evicted first.

Core budgets CTxMemPool::DynamicMemoryUsage(), witness included
(txmempool.cpp TrimToSize), and orders eviction by the worst chunk of TxGraph,
whose feerates are fee over sigop-adjusted WEIGHT (txmempool.cpp:1017
``FeePerWeight(fee, GetSigOpsAdjustedWeight(...))``; GetWorstMainChunk).

The budget half was already fixed on master by the DynamicMemoryUsage work
(6717f15, 5cb64a6): ``test_witness_bytes_count_against_maxmempool`` pins it.
The eviction-order half was not: ClusterManager chunked on ``entry.size``.
"""
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool

_VALUE = 100_000_000
_WITNESS_ITEM = 390_000  # bytes: one large tapscript-style witness push


class _StubDB:
    def __init__(self, utxos):
        self._u = utxos

    def get_utxo(self, txid, vout):
        return self._u.get((txid, vout))

    def get_median_time_past(self, height):
        return 0


class _StubValidator:
    """Accepts every script, so the test isolates the pool's accounting."""

    def __init__(self, utxos):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


def _prev(i: int) -> bytes:
    return bytes([0x10 + i]) + b"\x00" * 31


def _tx(i: int, fee: int, witness: bool) -> Transaction:
    txin = TxIn(prev_txid=_prev(i), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD,
                witness=[b"\x00" * _WITNESS_ITEM, b"\x51"] if witness else None)
    return Transaction(
        txid=bytes([0xB0 + i]) + b"\x00" * 31,
        version=2, locktime=0, inputs=[txin],
        outputs=[TxOut(value=_VALUE - fee, script_pubkey=b"\x51")],
        has_witness=witness,
    )


def _fee_for(feerate_sat_vb: float, i: int, witness: bool) -> int:
    probe = _tx(i, 1000, witness)
    return int(feerate_sat_vb * probe.get_vsize()) + 1


def _pool(n: int, max_size: int) -> Mempool:
    utxos = {(_prev(i), 0): {"value": _VALUE, "script_pubkey": b"\x51", "height": 1,
                             "is_coinbase": False} for i in range(n)}
    return Mempool(_StubValidator(utxos), max_size=max_size,
                   require_standard=False, full_rbf=True)


def test_witness_bytes_count_against_maxmempool():
    """Five ~390 KB-witness spends exceed a 1 MB -maxmempool: the pool either
    accounts their witness bytes or trims, it does not hold ~2 MB as ~500 B."""
    txs = [_tx(i, _fee_for(2.0, i, True), True) for i in range(5)]
    witness_total = sum(len(tx.serialize_with_witness()) for tx in txs)
    assert witness_total > 1_900_000
    pool = _pool(5, max_size=1_000_000)
    for tx in txs:
        pool.add_transaction(tx, 200)
    held = sum(len(pool.transactions[t].tx.serialize_with_witness()) for t in pool.transactions)
    assert pool.get_memory_usage() <= 1_000_000
    assert held <= 1_000_000, f"pool holds {held} witness-serialized bytes under a 1 MB limit"
    assert len(pool.transactions) < 5


def test_witness_heavy_low_feerate_tx_is_evicted_before_honest_tx():
    """A 1 sat/vB witness-heavy spend is the worst chunk, not a 10 sat/vB
    witness-less spend: Core's chunk feerate is fee over weight."""
    honest = _tx(0, _fee_for(10.0, 0, False), False)
    heavy = _tx(1, _fee_for(1.0, 1, True), True)
    # Its fee is higher in absolute terms; per stripped byte it looks ~1000x
    # the honest feerate, per vbyte it is a tenth of it.
    assert heavy.get_vsize() > 90_000 and len(heavy.serialize()) < 100

    sizing = _pool(2, max_size=10**9)
    for tx in (honest, heavy):
        ok, err = sizing.add_transaction(tx, 200)
        assert ok, err
    worst = sizing._cluster_manager.get_worst_chunk()
    assert worst is not None
    assert worst[0].txids == {heavy.txid}, "worst chunk is not the 1 sat/vB witness-heavy tx"

    # -maxmempool one byte under both: TrimToSize must drop the heavy one.
    limit = sizing.get_memory_usage() - 1
    pool = _pool(2, max_size=limit)
    ok, err = pool.add_transaction(honest, 200)
    assert ok, err
    pool.add_transaction(heavy, 200)
    assert honest.txid in pool.transactions, "10 sat/vB tx evicted ahead of a 1 sat/vB one"
    assert heavy.txid not in pool.transactions


def test_witness_heavy_replacement_does_not_beat_chunk_on_stripped_size():
    """RBF measures the replacement against the chunk it displaces in the same
    unit as the chunk feerate.  A ~0.2 sat/vB witness-heavy replacement of a
    10 sat/vB transaction pays more absolute fee but a far lower feerate, so
    it does not improve the feerate diagram and Core rejects it."""
    victim = _tx(0, _fee_for(10.0, 0, False), False)
    victim_fee = _VALUE - victim.outputs[0].value
    txin = TxIn(prev_txid=_prev(0), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD,
                witness=[b"\x00" * _WITNESS_ITEM, b"\x51"])
    replacement = Transaction(
        txid=b"\xc0" + b"\x00" * 31, version=2, locktime=0, inputs=[txin],
        outputs=[TxOut(value=_VALUE - victim_fee - 20_000, script_pubkey=b"\x51")],
        has_witness=True,
    )
    assert (victim_fee + 20_000) / replacement.get_vsize() < 1.0

    pool = _pool(1, max_size=10**9)
    ok, err = pool.add_transaction(victim, 200)
    assert ok, err
    ok, _err = pool.add_transaction(replacement, 200)
    assert not ok, "a 0.2 sat/vB replacement displaced a 10 sat/vB transaction"
    assert victim.txid in pool.transactions


def test_honest_replacement_of_witness_heavy_tx_improves_diagram():
    """The reverse role: a 1 sat/vB witness-heavy transaction must not pin
    its outpoint against an honest replacement paying ~186 sat/vB and more
    absolute fee.  On stripped size the victim looked ~1600 sat/B, so the
    diagram check rejected the replacement; on vsize Core accepts it."""
    victim = _tx(0, _fee_for(1.0, 0, True), True)
    victim_fee = _VALUE - victim.outputs[0].value
    fee = victim_fee + 20_000
    per = (_VALUE - fee) // 20
    outs = [TxOut(value=per, script_pubkey=b"\x51") for _ in range(20)]
    outs[0] = TxOut(value=_VALUE - fee - per * 19, script_pubkey=b"\x51")
    replacement = Transaction(
        txid=b"\xc1" + b"\x00" * 31, version=2, locktime=0,
        inputs=[TxIn(prev_txid=_prev(0), prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=outs,
    )
    assert fee / replacement.get_vsize() > 100 * victim_fee / victim.get_vsize()

    pool = _pool(1, max_size=10**9)
    ok, err = pool.add_transaction(victim, 200)
    assert ok, err
    ok, err = pool.add_transaction(replacement, 200)
    assert ok, f"honest replacement of a 1 sat/vB witness-heavy tx rejected: {err}"
    assert replacement.txid in pool.transactions
    assert victim.txid not in pool.transactions


def test_block_template_orders_and_caps_witness_heavy_tx_by_vsize():
    """get_block_template_txs picks chunks in Core's order: chunk feerate is
    fee over vsize (BlockAssembler walks TxGraph chunks by FeePerWeight), so a
    10 sat/vB witness-less spend comes before a 1 sat/vB witness-heavy one.
    On stripped size the heavy spend looked ~1600 sat/B and led the template.

    The chunk weight is 4 * vsize, so a max_weight between the two (10000 WU)
    keeps the honest tx and drops the ~390 KWU heavy one.  On stripped size
    the heavy tx weighed 4 * 61 WU and fitted under the same cap."""
    honest = _tx(0, _fee_for(10.0, 0, False), False)
    heavy = _tx(1, _fee_for(1.0, 1, True), True)
    honest_fee = _VALUE - honest.outputs[0].value
    heavy_fee = _VALUE - heavy.outputs[0].value
    assert honest.get_vsize() * 4 < 10_000 < heavy.get_vsize() * 4
    assert len(heavy.serialize()) * 4 + honest.get_vsize() * 4 < 10_000

    pool = _pool(2, max_size=10**9)
    for tx in (honest, heavy):
        ok, err = pool.add_transaction(tx, 200)
        assert ok, err

    txs, fee = pool.get_block_template_txs()
    assert [t.txid for t in txs] == [honest.txid, heavy.txid], \
        "1 sat/vB witness-heavy tx ordered ahead of a 10 sat/vB tx"
    assert fee == honest_fee + heavy_fee

    txs, fee = pool.get_block_template_txs(max_weight=10_000)
    assert [t.txid for t in txs] == [honest.txid], \
        "a ~390 KWU witness-heavy tx fitted under a 10000 WU template cap"
    assert fee == honest_fee
