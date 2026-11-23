"""Relayed txs already rejected are not re-validated; fee floors run before scripts.

Audit record ``ouroboros:mempool:no-recent-rejects-cache-script-before-fee``
(2026-11-09): the P2P tx handler had no reject filter, and
``Mempool._add_transaction_inner`` verified every script before it looked at
the fee floors.  A peer resending one script-failing tx made the node run
full validation, signatures included, on every copy; a zero-fee tx cost a
full script check before being refused for its fee.

Core:

* ``node/txdownloadman_impl.cpp`` ``ReceivedTx`` drops a tx whose wtxid is in
  ``m_lazy_recent_rejects`` (or the reconsiderable filter) before
  ``AcceptToMemoryPool``; ``MempoolRejectedTx`` inserts the wtxid (never for
  TX_MISSING_INPUTS or TX_WITNESS_STRIPPED); ``ActiveTipChange`` resets both.
* ``validation.cpp`` ``MemPoolAccept::PreChecks`` ends with ``CheckFeeRate``;
  ``PolicyScriptChecks`` runs after it.

These tests drive the REAL tx closure from ``BitcoinNode._register_handlers``
over the REAL ``Mempool``; only the validator's script step is faked, and it
counts how often scripts are verified.
"""
from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import tests.conftest  # noqa: F401  (installs the sync stub first)
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool
from ouroboros.p2p_messages import TxMessage
from ouroboros.validation import TransactionValidator

FUND = b"\x42" * 32
FUND_VALUE = 100_000
TIP = 500_000
TIP_HASH_A = b"\xaa" * 32
TIP_HASH_B = b"\xbb" * 32


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _tx(value: int, *, witness: list[bytes] | None = None,
        prev=(FUND, 0)) -> Transaction:
    tx = Transaction(
        txid=b"", version=2, locktime=0,
        inputs=[TxIn(prev_txid=prev[0], prev_vout=prev[1], script_sig=b"",
                     sequence=0xFFFFFFFF, witness=witness)],
        outputs=[TxOut(value=value, script_pubkey=b"\x51")],
        has_witness=witness is not None,
    )
    tx.txid = _dsha(tx.serialize())
    return tx


class _StubDB:
    def __init__(self, utxos):
        self._utxos = utxos

    def get_utxo(self, txid, vout):
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self._utxos.get(op) for op in outpoints]

    def get_median_time_past(self, height):
        return 1_700_000_000


class _CountingValidator(TransactionValidator):
    """The real validator, except the script step: a call that verifies
    scripts (``skip_scripts`` false) is counted and fails for any wtxid in
    ``bad_scripts`` with the validator's own script-failure token."""

    def __init__(self, db):
        super().__init__(db=db, network="mainnet")
        self.script_runs = 0
        self.bad_scripts: set[bytes] = set()

    def validate_transaction(self, tx, height, block_mtp=0, *args,
                             skip_scripts=False, **kwargs):
        ok, err = super().validate_transaction(
            tx, height, block_mtp, *args, skip_scripts=True, **kwargs)
        if not ok or skip_scripts:
            return ok, err
        self.script_runs += 1
        if tx.get_wtxid() in self.bad_scripts:
            return False, "Invalid signature for input 0"
        return True, ""


def _pool():
    db = _StubDB({
        (FUND, 0): {"value": FUND_VALUE, "script_pubkey": b"\x51",
                    "height": 499_000, "is_coinbase": False},
    })
    v = _CountingValidator(db)
    return Mempool(validator=v, max_size=300_000_000, require_standard=False,
                   full_rbf=True)


class _FakePeer:
    def __init__(self, host="203.0.113.7"):
        self.host, self.port, self.network = host, 8333, "mainnet"
        self.handlers = {}
        self.peer_feefilter = 0

    def register_handler(self, command, fn):
        self.handlers[command] = fn

    async def send_message(self, msg):
        pass


class _CountingMempool:
    """A mempool that only counts calls and answers one fixed reason."""

    def __init__(self, reason):
        self.reason = reason
        self.calls = 0
        self.transactions = {}

    def __len__(self):
        return 0

    def add_transaction(self, tx, height, peer=None):
        self.calls += 1
        return False, self.reason


def _node(mempool):
    from ouroboros.node import BitcoinNode

    peer = _FakePeer()
    tip = {"hash": TIP_HASH_A}
    punished = []
    fake = SimpleNamespace(
        peer_manager=SimpleNamespace(
            get_all_ready_peers=lambda: [peer],
            set_inbound_peer_handler=lambda fn: None,
            misbehaving=lambda *a: punished.append(a),
        ),
        block_filter_index=None,
        mempool=mempool,
        db=SimpleNamespace(get_best_block=lambda: (tip["hash"], TIP)),
        pruner=None,
        zmq_notifier=None,
        network="mainnet",
    )
    BitcoinNode._register_handlers(fake)

    def send(tx):
        msg = TxMessage(transaction=tx).to_network_message("mainnet")
        asyncio.run(peer.handlers["tx"](msg))

    return send, tip, punished


# ---------------------------------------------------------------------------
# (a) the item's test: one script-failing tx resent 10 times -> 1 validation
# ---------------------------------------------------------------------------


def test_resent_script_failing_tx_is_validated_once():
    pool = _pool()
    bad = _tx(90_000, witness=[b"\x01" * 72])
    pool.validator.bad_scripts.add(bad.get_wtxid())
    send, _tip, punished = _node(pool)
    for _ in range(10):
        send(bad)
    # master: 10 (every resend re-ran the scripts)
    assert pool.validator.script_runs == 1
    assert bad.get_txid() not in pool.transactions
    assert punished == []


# ---------------------------------------------------------------------------
# (b) the item's test: a below-min-relay-fee tx -> 0 script validations
# ---------------------------------------------------------------------------


def test_below_min_relay_fee_tx_never_runs_scripts():
    pool = _pool()
    zero_fee = _tx(FUND_VALUE)  # fee 0 < min relay fee
    ok, err = pool.add_transaction(zero_fee, TIP)
    assert not ok and err == "min relay fee not met", err
    # master: 1 (scripts ran before the fee floor)
    assert pool.validator.script_runs == 0


def test_below_min_relay_fee_via_handler_runs_no_scripts_and_is_not_retried():
    pool = _pool()
    zero_fee = _tx(FUND_VALUE)
    send, _tip, _p = _node(pool)
    for _ in range(5):
        send(zero_fee)
    assert pool.validator.script_runs == 0


def test_rolling_mempool_min_fee_runs_before_scripts():
    pool = _pool()
    pool._get_min_fee_inner = lambda: 50_000  # sat/kvB, above min relay
    low = _tx(FUND_VALUE - 2_000)  # pays min relay, not the rolling floor
    ok, err = pool.add_transaction(low, TIP)
    assert not ok and err == "mempool min fee not met", err
    assert pool.validator.script_runs == 0


def test_paying_tx_still_runs_its_scripts_and_is_accepted():
    """Control: the reorder skips scripts only for a tx the fee floor
    refuses; a paying tx is script-checked exactly once and accepted."""
    pool = _pool()
    good = _tx(90_000)
    ok, err = pool.add_transaction(good, TIP)
    assert ok, err
    assert pool.validator.script_runs == 1


def test_script_failure_with_enough_fee_is_still_refused():
    """Control: fee first does not wave a bad-script tx through."""
    pool = _pool()
    bad = _tx(90_000, witness=[b"\x02"])
    pool.validator.bad_scripts.add(bad.get_wtxid())
    ok, err = pool.add_transaction(bad, TIP)
    assert not ok and err == "Invalid signature for input 0"
    assert pool.validator.script_runs == 1


def test_overspend_is_refused_before_scripts():
    """CheckTxInputs (bad-txns-in-belowout) precedes PolicyScriptChecks in
    Core; the non-script pass reports it without verifying a script."""
    pool = _pool()
    over = _tx(FUND_VALUE + 1)
    ok, err = pool.add_transaction(over, TIP)
    assert not ok and err.startswith("bad-txns-in-belowout"), err
    assert pool.validator.script_runs == 0


# ---------------------------------------------------------------------------
# Filter semantics
# ---------------------------------------------------------------------------


def test_tip_change_resets_the_filter():
    pool = _pool()
    bad = _tx(90_000, witness=[b"\x01"])
    pool.validator.bad_scripts.add(bad.get_wtxid())
    send, tip, _p = _node(pool)
    send(bad)
    send(bad)
    assert pool.validator.script_runs == 1
    tip["hash"] = TIP_HASH_B  # Core ActiveTipChange
    send(bad)
    send(bad)
    assert pool.validator.script_runs == 2


def test_mutated_witness_is_a_different_wtxid():
    """Only the wtxid is recorded: a copy with another witness (a malleated
    version) is validated on its own."""
    pool = _pool()
    bad = _tx(90_000, witness=[b"\x01"])
    other = _tx(90_000, witness=[b"\x03"])
    assert bad.get_txid() == other.get_txid()
    assert bad.get_wtxid() != other.get_wtxid()
    pool.validator.bad_scripts.add(bad.get_wtxid())
    send, _tip, _p = _node(pool)
    send(bad)
    send(other)
    assert pool.validator.script_runs == 2
    assert other.get_txid() in pool.transactions


def test_script_failure_without_witness_is_not_recorded():
    """Possibly witness-stripped (Core TX_WITNESS_STRIPPED is never recorded):
    wtxid == txid, so recording it could block the real witnessed tx."""
    pool = _pool()
    stripped = _tx(90_000)
    pool.validator.bad_scripts.add(stripped.get_wtxid())
    send, _tip, _p = _node(pool)
    for _ in range(3):
        send(stripped)
    assert pool.validator.script_runs == 3


def _calls_for(reason, n=4):
    mp = _CountingMempool(reason)
    send, _tip, _p = _node(mp)
    tx = _tx(90_000, witness=[b"\x01"])
    for _ in range(n):
        send(tx)
    return mp.calls


def test_orphan_is_not_recorded():
    # TX_MISSING_INPUTS goes to the orphanage, never the reject filter.
    assert _calls_for("orphan") == 4


def test_internal_fault_is_not_recorded():
    from ouroboros.fatal import INTERNAL_ERROR_MARKER
    assert _calls_for(f"{INTERNAL_ERROR_MARKER}: utxo read failed") == 4
    assert _calls_for("missing-ancestor-header") == 4


def test_duplicate_rejects_are_not_recorded():
    assert _calls_for("txn-already-in-mempool") == 4
    assert _calls_for("Already in orphan pool") == 4


def test_policy_and_premature_rejects_are_recorded():
    assert _calls_for("non-final") == 1
    assert _calls_for("scriptpubkey") == 1
    assert _calls_for("bad-witness-nonstandard") == 1
    assert _calls_for("mempool min fee not met") == 1


def test_filter_is_bounded():
    from ouroboros.recent_rejects import RecentRejects

    rr = RecentRejects(capacity=3)
    rr.tip_changed(TIP_HASH_A)
    keys = [bytes([i]) * 32 for i in range(5)]
    for k in keys:
        assert rr.record(k, "non-final", True)
    assert not rr.contains(keys[0]) and not rr.contains(keys[1])
    assert all(rr.contains(k) for k in keys[2:])


class _TipMovingMempool(_CountingMempool):
    """A block connects while this tx is in ATMP (the handler runs ATMP in a
    worker thread, so other peers' handlers and block connection interleave)."""

    def __init__(self, reason, tip):
        super().__init__(reason)
        self.tip = tip
        self.node = None

    def add_transaction(self, tx, height, peer=None):
        self.calls += 1
        if self.calls == 1:
            # Block B connects, and another peer's tx reaches the handler
            # first: the filter is reset and re-stamped with B.
            self.tip["hash"] = TIP_HASH_B
            self.node.recent_rejects.tip_changed(TIP_HASH_B)
        return False, self.reason


def test_verdict_from_an_old_tip_is_not_recorded_under_the_new_tip():
    """X is refused 'non-final' at tip A, but block B connects before the
    verdict is recorded.  X may be final at B, so it must be validated again,
    not dropped until the next block."""
    tip = {"hash": TIP_HASH_A}
    mp = _TipMovingMempool("non-final", tip)
    from ouroboros.node import BitcoinNode

    peer = _FakePeer()
    fake = SimpleNamespace(
        peer_manager=SimpleNamespace(
            get_all_ready_peers=lambda: [peer],
            set_inbound_peer_handler=lambda fn: None,
            misbehaving=lambda *a: None,
        ),
        block_filter_index=None,
        mempool=mp,
        db=SimpleNamespace(get_best_block=lambda: (tip["hash"], TIP)),
        pruner=None,
        zmq_notifier=None,
        network="mainnet",
    )
    BitcoinNode._register_handlers(fake)
    mp.node = fake
    tx = _tx(90_000, witness=[b"\x01"])
    msg = TxMessage(transaction=tx).to_network_message("mainnet")
    asyncio.run(peer.handlers["tx"](msg))   # verdict at A, tip now B
    asyncio.run(peer.handlers["tx"](msg))   # validated at B, recorded
    asyncio.run(peer.handlers["tx"](msg))   # filtered
    assert mp.calls == 2
