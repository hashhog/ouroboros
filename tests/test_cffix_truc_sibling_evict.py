"""TRUC sibling eviction decides before it removes anything.

``_try_sibling_eviction`` checked only that the newcomer N paid more absolute
fee than the sibling S and that the difference covered the incremental relay
fee on N's *stripped* (non-witness) size.  It then removed S and re-ran the
whole admission for N.  When that re-admission failed (for example on the
min relay fee, which is charged on vsize), S was already gone and was never
put back, so one rejected transaction cleared an honest child out of the pool.
The removal also used ``_skip_recount=True`` with no recount afterwards, so the
parent's ``descendant_count`` went stale (3 after a successful eviction).

Bitcoin Core runs ``CheckFeeRate`` (validation.cpp, PreChecks, before
``SingleTRUCChecks``) and then treats the sibling as one more conflict in
``ReplacementChecks``: ``PaysForRBF`` on the sigop-adjusted vsize with the
incremental relay feerate, reject token "insufficient fee (including sibling
eviction)".  Nothing leaves the pool until every check has passed.

The controls pin the other side: an eviction that pays for itself still
happens, and leaves the parent with descendant_count 2.
"""

from __future__ import annotations

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool

HEIGHT = 200
COIN_VALUE = 100_000_000
SEQ = 0xFFFFFFFD
COIN = (0x0F000000).to_bytes(4, "big") + b"\xcd" * 28


def _txid(tag: int) -> bytes:
    return tag.to_bytes(4, "big") + b"\xcd" * 28


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


def _pool() -> Mempool:
    utxos = {(COIN, 0): {"value": COIN_VALUE, "script_pubkey": b"\x51",
                         "height": 1, "is_coinbase": False}}
    return Mempool(validator=_StubValidator(utxos), require_standard=False)


def _setup():
    """v3 parent P with two outputs, and its child S paying the min relay fee."""
    pool = _pool()
    half = (COIN_VALUE - 10_000) // 2
    parent = Transaction(
        txid=_txid(1), version=3, locktime=0,
        inputs=[TxIn(prev_txid=COIN, prev_vout=0, script_sig=b"", sequence=SEQ)],
        outputs=[TxOut(value=half, script_pubkey=b"\x51"),
                 TxOut(value=half, script_pubkey=b"\x51")],
    )
    ok, err = pool.add_transaction(parent, HEIGHT)
    assert ok, err

    sibling = Transaction(
        txid=_txid(2), version=3, locktime=0,
        inputs=[TxIn(prev_txid=parent.get_txid(), prev_vout=0, script_sig=b"",
                     sequence=SEQ)],
        outputs=[TxOut(value=0, script_pubkey=b"\x51")],
    )
    s_vsize = sibling.get_vsize()
    s_fee = s_vsize * 100 // 1000  # DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB
    sibling.outputs[0].value = half - s_fee
    ok, err = pool.add_transaction(sibling, HEIGHT)
    assert ok, err
    assert pool.transactions[sibling.get_txid()].fee == s_fee
    assert pool.transactions[parent.get_txid()].descendant_count == 2
    return pool, parent, sibling, half, s_fee


def _newcomer(parent: Transaction, half: int, fee: int,
              witness_bytes: int = 3_194) -> Transaction:
    """Spends P's second output: 100-byte stripped size, ~900 vB vsize."""
    tx = Transaction(
        txid=_txid(3), version=3, locktime=0,
        inputs=[TxIn(prev_txid=parent.get_txid(), prev_vout=1, script_sig=b"",
                     sequence=SEQ, witness=[b"\x00" * witness_bytes])],
        outputs=[TxOut(value=half - fee, script_pubkey=b"\x51" + b"\x00" * 39)],
        has_witness=True,
    )
    assert len(tx.serialize()) == 100
    return tx


def test_rejected_sibling_eviction_keeps_the_sibling():
    pool, parent, sibling, half, s_fee = _setup()
    new = _newcomer(parent, half, s_fee + 11)
    assert 880 <= new.get_vsize() <= 920

    # 11 sat covers the incremental fee on the 100 stripped bytes (10 sat),
    # but N's 900 vB need 90 sat for the min relay fee alone.
    ok, err = pool.add_transaction(new, HEIGHT)
    assert not ok
    assert new.get_txid() not in pool.transactions
    assert sibling.get_txid() in pool.transactions, "rejected N evicted S"
    assert pool.transactions[parent.get_txid()].descendant_count == 2
    assert pool.transactions[parent.get_txid()].children == {sibling.get_txid()}
    # Core's CheckFeeRate token, from the check that runs before any eviction.
    assert err == "min relay fee not met", err


def test_sibling_eviction_incremental_fee_is_charged_on_vsize():
    pool, parent, sibling, half, s_fee = _setup()
    new = _newcomer(parent, half, 0)
    vsize = new.get_vsize()
    needed = -((-vsize * 100) // 1000)  # incremental relay fee on vsize, rounded up
    # Clears the min relay fee on its own, but pays one sat less than PaysForRBF
    # wants on top of the sibling's fee.
    fee = s_fee + needed - 1
    assert fee >= vsize * 100 // 1000
    new = _newcomer(parent, half, fee)

    ok, err = pool.add_transaction(new, HEIGHT)
    assert not ok
    assert err.startswith("insufficient fee (including sibling eviction)"), err
    assert sibling.get_txid() in pool.transactions
    assert new.get_txid() not in pool.transactions
    assert pool.transactions[parent.get_txid()].descendant_count == 2


def test_sibling_eviction_that_pays_still_evicts_and_recounts_parent():
    pool, parent, sibling, half, s_fee = _setup()
    new = _newcomer(parent, half, 0)
    needed = -((-new.get_vsize() * 100) // 1000)
    new = _newcomer(parent, half, s_fee + needed)

    ok, err = pool.add_transaction(new, HEIGHT)
    assert ok, err
    assert sibling.get_txid() not in pool.transactions
    assert new.get_txid() in pool.transactions
    p = pool.transactions[parent.get_txid()]
    assert p.children == {new.get_txid()}
    assert p.descendant_count == 2
    assert p.descendant_size == p.size + pool.transactions[new.get_txid()].size



def test_readmission_failure_after_removal_restores_the_sibling():
    """Any gate after the TRUC check that still refuses N puts S back.

    The fee checks now run before the removal; this pins the second line of
    defence by making a later gate (the cluster limit) refuse N only.
    """
    pool, parent, sibling, half, s_fee = _setup()
    new = _newcomer(parent, half, 0)
    needed = -((-new.get_vsize() * 100) // 1000)
    new = _newcomer(parent, half, s_fee + needed)

    real = pool._check_cluster_limit

    def refuse_new(tx, *a, **kw):
        if tx.get_txid() == new.get_txid():
            return False, "too-large-cluster"
        return real(tx, *a, **kw)

    pool._check_cluster_limit = refuse_new
    ok, err = pool.add_transaction(new, HEIGHT)
    assert not ok
    assert new.get_txid() not in pool.transactions
    assert sibling.get_txid() in pool.transactions, "S lost after failed re-admission"
    p = pool.transactions[parent.get_txid()]
    assert p.children == {sibling.get_txid()}
    assert p.descendant_count == 2
    assert err == "too-large-cluster", err
