"""getmempoolinfo ``usage`` counts the chunks Core's TxGraph holds.

Item refill-20261116-ouroboros-policy, core-regtest row
``warden_e/e-invalidate/info:usage`` (Core 75288, ouroboros 75096).

Core's DynamicMemoryUsage() includes TxGraph's m_main_chunkindex, one set node
per chunk of every cluster (txgraph.cpp GetMainMemoryUsage), and TxGraph
chunks each cluster's optimal linearization of modified fee and
sigop-adjusted weight.  ouroboros counted chunks with ClusterManager's greedy
ancestor-set chunking of base fee and vsize.  On the warden_e pool (a parent
with 64 outputs back in the pool after invalidateblock, children 1..63) that
gives 27 chunks where Core has 30, so usage came out 3 x 64 bytes short.

The fixture is Core v31.1's own data from that scenario, recorded through the
core-regtest harness: the raw transactions, getmempoolinfo before and after
the invalidate, and getmempoolcluster's chunk sizes.
"""
import json
from pathlib import Path

from ouroboros.mempool import Mempool, optimal_chunks
from ouroboros.p2p_messages import TxMessage

_FIXTURE = Path(__file__).parent / "fixtures" / "core31_warden_e_invalidate_usage.json"
_FX = json.loads(_FIXTURE.read_text())
_TIP = 101  # the parent was confirmed in block 102; invalidateblock leaves tip 101


def _tx(raw_hex):
    return TxMessage.from_payload(bytes.fromhex(raw_hex)).transaction


class _StubDB:
    def __init__(self):
        self.utxos = {}

    def get_utxo(self, txid, vout):
        return self.utxos.get((txid, vout))

    def get_median_time_past(self, height):
        return 0


class _StubValidator:
    def __init__(self):
        self.db = _StubDB()

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


def _coin(value, script):
    return {"value": value, "script_pubkey": script, "height": 1, "is_coinbase": False}


def _invalidated_pool():
    """The pool as Core holds it after the scenario: the 64 children are
    admitted while the parent is confirmed, then the parent's block is
    disconnected and the parent re-added (MaybeUpdateMempoolForReorg), which
    makes a 65-tx cluster that the trim brings back to 64."""
    parent = _tx(_FX["parent"])
    children = [_tx(h) for h in _FX["children"]]
    validator = _StubValidator()
    utxos = validator.db.utxos
    ptxid = parent.get_txid()
    for i, out in enumerate(parent.outputs):
        utxos[(ptxid, i)] = _coin(out.value, out.script_pubkey)
    pool = Mempool(validator, max_size=300_000_000, require_standard=False, full_rbf=True)
    for child in children:
        ok, err = pool.add_transaction(child, _TIP + 1)
        assert ok, err
    assert pool.dynamic_memory_usage() == _FX["core_before_invalidate"]["usage"]

    # Disconnect the parent's block: its outputs leave the UTXO set and the
    # coinbase output it spends comes back.
    for i in range(len(parent.outputs)):
        del utxos[(ptxid, i)]
    fund = _FX["funding"]
    utxos[(bytes.fromhex(fund["txid"])[::-1], fund["vout"])] = _coin(
        fund["value"], bytes.fromhex(fund["script_pubkey"]))
    pool.update_for_reorg([parent], _TIP)
    return pool, parent, children


def test_pool_after_invalidate_is_cores():
    # Guard (passes on master too): same transactions as Core, so the usage
    # test below compares like with like.
    pool, _parent, _children = _invalidated_pool()
    have = sorted(t[::-1].hex() for t in pool.transactions)
    assert have == _FX["core_pool"]
    info = _FX["core_after_invalidate"]
    assert len(pool.transactions) == info["size"]


def test_txgraph_chunking_is_cores_getmempoolcluster():
    # Guard (passes on master too): the optimal chunking getmempoolentry uses
    # is Core's getmempoolcluster layout (one 35-tx chunk, 29 singletons).
    pool, parent, _children = _invalidated_pool()
    cluster = set(pool.transactions)
    fee = {t: int(pool.transactions[t].fee) for t in cluster}
    size = {t: int(pool.transactions[t].sigop_adjusted_weight) for t in cluster}
    parents = {t: set(pool.transactions[t].parents) & cluster for t in cluster}
    sizes = [len(c) for c, _f, _s in optimal_chunks(cluster, fee, size, parents)]
    assert sizes == _FX["core_cluster_chunk_sizes"]


def test_usage_after_invalidate_equals_core_31():
    pool, _parent, _children = _invalidated_pool()
    assert pool.dynamic_memory_usage() == _FX["core_after_invalidate"]["usage"]


def test_prioritise_recounts_the_cluster_usage_term():
    # A fee delta moves TxGraph's chunking (Core feeds it the modified fee,
    # txmempool.cpp PrioritiseTransaction -> SetTransactionFee), so the
    # cached per-cluster usage term must be recomputed, not reused.
    pool, _parent, children = _invalidated_pool()
    before = pool.dynamic_memory_usage()  # fills the per-cluster cache
    for child in children[1:30]:
        pool.prioritise_transaction(child.get_txid(), 1_000_000)
    cluster = set(pool.transactions)
    fee = {t: pool.get_modified_fee(t) for t in cluster}
    size = {t: int(pool.transactions[t].sigop_adjusted_weight) for t in cluster}
    parents = {t: set(pool.transactions[t].parents) & cluster for t in cluster}
    chunks_now = len(optimal_chunks(cluster, fee, size, parents))
    assert chunks_now != len(_FX["core_cluster_chunk_sizes"])
    after = pool.dynamic_memory_usage()
    # Only the chunk-index share moves: one 64-byte node per chunk.
    assert after - before == 64 * (chunks_now - len(_FX["core_cluster_chunk_sizes"]))
    pool._cluster_manager.usage_reset = True
    assert pool.dynamic_memory_usage() == after
