"""-maxmempool (MB) must size the mempool, as in Core's mempool_args.cpp.

Core: max_size_bytes = -maxmempool * 1'000'000, default 300.  ouroboros
hard-coded Mempool(max_size=300_000_000) and had no such option.
"""
from ouroboros import mempool as mp
from ouroboros.cli import start
from ouroboros.config import NodeConfig


def _helper():
    fn = getattr(mp, "max_mempool_bytes", None)
    assert fn is not None, "mempool.max_mempool_bytes missing: no -maxmempool support"
    return fn


def test_maxmempool_megabytes_to_bytes():
    assert _helper()({"maxmempool": 5}) == 5_000_000


def test_maxmempool_default_is_300mb():
    assert _helper()({}) == 300_000_000


def test_cli_start_has_maxmempool_option():
    assert "maxmempool" in {p.name for p in start.params}


def test_conf_file_maxmempool(tmp_path):
    conf = tmp_path / "ouroboros.conf"
    conf.write_text("[network]\nmaxmempool=7\n")
    cfg = NodeConfig(config_path=str(conf), data_dir=str(tmp_path)).to_dict()
    assert cfg.get("maxmempool") == 7


# ---------------------------------------------------------------------------
# The cap must hold on the single-tx path (sendrawtransaction / P2P).
#
# Core AcceptSingleTransaction (validation.cpp): the fee is checked against the
# CURRENT pool minimum (PreChecks/CheckFeeRate), the tx is inserted
# (FinalizeSubpackage), and only then LimitMempoolSize() trims to max_size_bytes;
# if the new tx itself was trimmed it is reported "mempool full".  ouroboros
# evicted tx_size bytes BEFORE the fee check and never trimmed after insert, so
# the pool could stay above the cap, and a tx that was then rejected had
# already pushed out one that fit.
# ---------------------------------------------------------------------------

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402


class _StubDB:
    def __init__(self, utxos):
        self._u = utxos

    def get_utxo(self, txid, vout):
        return self._u.get((txid, vout))

    def get_median_time_past(self, height):
        return 0


class _StubValidator:
    def __init__(self, utxos):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


_VALUE = 1_000_000


def _funding(n):
    return [bytes([i + 1]) * 32 for i in range(n)]


def _tx(prev, fee, n_outputs=1):
    per = (_VALUE - fee) // n_outputs
    outs = [TxOut(value=per, script_pubkey=b"\x51") for _ in range(n_outputs)]
    outs[0] = TxOut(value=_VALUE - fee - per * (n_outputs - 1), script_pubkey=b"\x51")
    # This Transaction carries its txid; derive a distinct one per tx.
    return Transaction(
        txid=bytes([0xAA]) + prev[:1] + fee.to_bytes(4, "little") + b"\x00" * 26,
        version=2, locktime=0,
        inputs=[TxIn(prev_txid=prev, prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD)],
        outputs=outs,
    )


def _pool(prevs, max_size):
    utxos = {(p, 0): {"value": _VALUE, "script_pubkey": b"\x51", "height": 1,
                      "is_coinbase": False} for p in prevs}
    return Mempool(_StubValidator(utxos), max_size=max_size,
                   require_standard=False, full_rbf=True)


def test_tx_larger_than_cap_is_not_kept():
    prevs = _funding(1)
    big = _tx(prevs[0], 20_000, n_outputs=40)
    size = len(big.serialize())
    pool = _pool(prevs, max_size=size // 2)
    ok, err = pool.add_transaction(big, 100)
    assert not ok and err == "mempool full", (ok, err)
    assert big.get_txid() not in pool.transactions
    assert pool.current_size <= pool.max_size


def test_zero_cap_keeps_nothing():
    prevs = _funding(1)
    pool = _pool(prevs, max_size=0)
    ok, err = pool.add_transaction(_tx(prevs[0], 10_000), 100)
    assert not ok and err == "mempool full", (ok, err)
    assert pool.current_size == 0 and not pool.transactions


def test_rejected_tx_does_not_shrink_pool():
    prevs = _funding(3)
    t1, t2 = _tx(prevs[0], 10_000), _tx(prevs[1], 10_000)
    size = len(t1.serialize())
    pool = _pool(prevs, max_size=2 * size + size // 2)
    assert pool.add_transaction(t1, 100) == (True, "")
    assert pool.add_transaction(t2, 100) == (True, "")
    # Lower feerate than both pool members: it is the one trimmed.
    t3 = _tx(prevs[2], 5_000)
    ok, err = pool.add_transaction(t3, 100)
    assert not ok and err == "mempool full", (ok, err)
    assert t1.get_txid() in pool.transactions
    assert t2.get_txid() in pool.transactions
    assert pool.current_size == 2 * size


def test_higher_fee_tx_displaces_worst_and_cap_holds():
    prevs = _funding(3)
    t1, t2 = _tx(prevs[0], 10_000), _tx(prevs[1], 9_000)
    size = len(t1.serialize())
    pool = _pool(prevs, max_size=2 * size + size // 2)
    assert pool.add_transaction(t1, 100) == (True, "")
    assert pool.add_transaction(t2, 100) == (True, "")
    t3 = _tx(prevs[2], 20_000)
    assert pool.add_transaction(t3, 100) == (True, "")
    assert t2.get_txid() not in pool.transactions  # lowest feerate evicted
    assert t1.get_txid() in pool.transactions
    assert pool.current_size <= pool.max_size


def test_conf_non_integer_maxmempool_falls_back_to_300(tmp_path):
    conf = tmp_path / "ouroboros.conf"
    conf.write_text("[network]\nmaxmempool=abc\n")
    cfg = NodeConfig(config_path=str(conf), data_dir=str(tmp_path)).to_dict()
    assert _helper()(cfg) == 300_000_000


def test_conf_negative_maxmempool_falls_back_to_300(tmp_path):
    conf = tmp_path / "ouroboros.conf"
    conf.write_text("[network]\nmaxmempool=-4\n")
    cfg = NodeConfig(config_path=str(conf), data_dir=str(tmp_path)).to_dict()
    assert _helper()(cfg) == 300_000_000


def _in_cluster_manager(pool, txid):
    return any(txid in c.txids for c in pool._cluster_manager._clusters.values())


def test_rbf_replacement_is_trimmed_to_cap():
    # The replacement path inserts on its own; it must be trimmed like any
    # other single tx (Core LimitMempoolSize after FinalizeSubpackage).
    prevs = _funding(2)
    t1, t2 = _tx(prevs[0], 10_000), _tx(prevs[1], 10_000)
    size = len(t1.serialize())
    pool = _pool(prevs, max_size=2 * size + size // 2)
    assert pool.add_transaction(t1, 100) == (True, "")
    assert pool.add_transaction(t2, 100) == (True, "")
    # Replaces t1, higher feerate than t2, fits alone but not next to t2.
    r = _tx(prevs[0], 50_000, n_outputs=9)
    assert size < len(r.serialize()) <= pool.max_size < len(r.serialize()) + size
    assert pool.add_transaction(r, 100) == (True, "")
    assert t1.get_txid() not in pool.transactions
    assert r.get_txid() in pool.transactions
    assert _in_cluster_manager(pool, r.get_txid())
    assert t2.get_txid() not in pool.transactions  # lowest feerate trimmed
    assert pool.current_size <= pool.max_size


def test_rbf_replacement_larger_than_cap_is_not_kept():
    prevs = _funding(1)
    t1 = _tx(prevs[0], 10_000)
    size = len(t1.serialize())
    pool = _pool(prevs, max_size=2 * size)
    assert pool.add_transaction(t1, 100) == (True, "")
    r = _tx(prevs[0], 200_000, n_outputs=40)
    assert len(r.serialize()) > pool.max_size
    ok, err = pool.add_transaction(r, 100)
    assert not ok and err == "mempool full", (ok, err)
    assert r.get_txid() not in pool.transactions
    assert pool.current_size <= pool.max_size


def test_package_rbf_parent_is_not_trimmed_mid_package():
    # Core SingleInPackageAccept runs with package_submission=true: package
    # members (a parent that replaces a pool tx included) are trimmed once at
    # the end of AcceptPackage, so a high-fee child can still carry a
    # low-feerate parent.  Trimming the parent on its own insert lost both
    # the package and the tx it replaced.
    prevs = _funding(2)
    t1 = _tx(prevs[0], 1_000)
    t2 = _tx(prevs[1], 60_000, n_outputs=10)
    pool = _pool(prevs, max_size=len(t1.serialize()) + len(t2.serialize()) + 40)
    assert pool.add_transaction(t1, 100) == (True, "")
    assert pool.add_transaction(t2, 100) == (True, "")
    parent = _tx(prevs[0], 3_000, n_outputs=6)           # replaces t1
    assert parent.get_txid() != t1.get_txid()
    out0 = parent.outputs[0].value
    child = Transaction(
        txid=b"\xcc" * 32, version=2, locktime=0,
        inputs=[TxIn(prev_txid=parent.get_txid(), prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=out0 - 80_000, script_pubkey=b"\x51")],
    )
    res = pool.accept_package([parent, child], 100)
    assert res.state == "valid", (res.state, res.message,
                                  {k.hex()[:8]: v.reject_reason for k, v in res.results.items()})
    assert parent.get_txid() in pool.transactions
    assert child.get_txid() in pool.transactions
    assert t1.get_txid() not in pool.transactions          # replaced
    assert t2.get_txid() not in pool.transactions          # end-of-package trim
    assert pool.current_size <= pool.max_size
