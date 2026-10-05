"""Relay punishment for rejected transactions follows Core's TxValidationResult.

Live, 2026-10-05 (ouroboros d94041f on mainnet): ~90 peer bans per hour, every
one ``invalid tx: <reason>`` with reasons that are policy or local state —
"Input not found" (2,678 in 30 h), "txn-already-in-mempool", "Already in orphan
pool", "non-final", "Replacement would worsen cluster feerate", "BIP 68 …".
``node.py``'s tx handler scored +10 for EVERY rejection except ``orphan``.

Core (``consensus/validation.h`` TxValidationResult; ``net_processing.cpp``
MaybePunishNodeForTx through v27, ProcessInvalidTx after) never punishes
policy, conflict, premature-spend or missing-inputs results — only
TX_CONSENSUS ever was.

The "Input not found" class was not even a rejection Core would make: 268 of
the 275 distinct missing prevouts in the 3 h journal were outputs of a tx
ouroboros had ALREADY ACCEPTED to its mempool.  The mempool's orphan gate
counts a mempool parent as present, but the TransactionValidator looked only
at the chain UTXO set, so every child of an unconfirmed parent was refused
and its relayer punished.  Core resolves inputs through CCoinsViewMemPool.

The handler tests drive the REAL tx closure built by
``BitcoinNode._register_handlers``; the mempool tests drive the real Mempool
over the real TransactionValidator.
"""
from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

import tests.conftest  # noqa: F401  (installs the sync stub first)
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool
from ouroboros.p2p_messages import TxMessage
from ouroboros.validation import TransactionValidator


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _tx(prev_txid: bytes, prev_vout: int, value: int, *, seq=0xFFFFFFFF,
        version=2) -> Transaction:
    tx = Transaction(
        txid=b"", version=version, locktime=0,
        inputs=[TxIn(prev_txid=prev_txid, prev_vout=prev_vout,
                     script_sig=b"", sequence=seq)],
        outputs=[TxOut(value=value, script_pubkey=b"\x51")],
    )
    tx.txid = _dsha(tx.serialize())
    return tx


# ---------------------------------------------------------------------------
# The real tx handler: who gets punished
# ---------------------------------------------------------------------------


class _FakePeer:
    def __init__(self, host="203.0.113.7"):
        self.host, self.port, self.network = host, 8333, "mainnet"
        self.handlers = {}
        self.sent = []
        self.peer_feefilter = 0

    def register_handler(self, command, fn):
        self.handlers[command] = fn

    async def send_message(self, msg):
        self.sent.append(msg)


class _RejectingMempool:
    def __init__(self, reason):
        self.reason = reason
        self.transactions = {}

    def __len__(self):
        return 0

    def add_transaction(self, tx, height, peer=None):
        return False, self.reason


def _run_tx_handler(reason):
    from ouroboros.node import BitcoinNode

    peer = _FakePeer()
    calls = []
    fake = SimpleNamespace(
        peer_manager=SimpleNamespace(
            get_all_ready_peers=lambda: [peer],
            set_inbound_peer_handler=lambda fn: None,
            misbehaving=lambda addr, score, why: calls.append((addr, score, why)),
        ),
        block_filter_index=None,
        mempool=_RejectingMempool(reason),
        db=SimpleNamespace(get_best_block=lambda: (b"\x00" * 32, 100)),
        pruner=None,
        zmq_notifier=None,
        network="mainnet",
    )
    BitcoinNode._register_handlers(fake)
    msg = TxMessage(transaction=_tx(b"\x11" * 32, 0, 1000)).to_network_message("mainnet")
    asyncio.run(peer.handlers["tx"](msg))
    return calls


# Every one of these was observed scoring an honest peer on mainnet (or is the
# same Core class).  Core never punishes any of them.
_UNPUNISHED = [
    "Input not found: " + "ab" * 32 + ":0",          # TX_MISSING_INPUTS
    "UTXO not found: abababababababab...:1",          # TX_MISSING_INPUTS
    "txn-already-in-mempool",                          # TX_CONFLICT
    "txn-same-nonwitness-data-in-mempool",             # TX_CONFLICT
    "txn-already-known",                               # TX_CONFLICT
    "Already in orphan pool",                          # TX_CONFLICT
    "non-final",                                       # TX_PREMATURE_SPEND
    "BIP 68 sequence lock not satisfied",              # TX_PREMATURE_SPEND
    "bad-txns-premature-spend-of-coinbase: tried to spend coinbase at depth 3",
    "min relay fee not met",                           # TX_MEMPOOL_POLICY
    "mempool min fee not met",                         # TX_MEMPOOL_POLICY
    "Replacement would worsen cluster feerate",        # TX_MEMPOOL_POLICY
    "Conflicting tx does not signal replaceability (BIP125)",
    "dust",                                            # TX_NOT_STANDARD
    "scriptpubkey",                                    # TX_NOT_STANDARD
    "bad-witness-nonstandard",                         # TX_WITNESS_MUTATED
    "missing-ancestor-header",                         # our own state
    # Mempool scripts run with STANDARD flags; without Core's mandatory-flag
    # re-run the failure is not provably consensus -> unknown, unpunished.
    "Invalid signature for input 0",
    "a reason this module has never seen",             # unknown -> never
]


@pytest.mark.parametrize("reason", _UNPUNISHED)
def test_policy_and_state_rejections_are_not_punished(reason):
    assert _run_tx_handler(reason) == []


def test_orphan_is_not_punished():
    assert _run_tx_handler("orphan") == []


# Negative control: the instrument above must be able to SEE a punishment.
# Consensus-invalid reasons (Core TX_CONSENSUS) are still scored.
@pytest.mark.parametrize("reason", [
    "coinbase",
    "bad-txns-inputs-duplicate",
    "bad-txns-vout-negative",
    "bad-txns-in-belowout: value in (100) < value out (200)",
    "bad-txns-inputvalues-outofrange",
])
def test_consensus_invalid_is_punished(reason):
    calls = _run_tx_handler(reason)
    assert len(calls) == 1, calls
    addr, score, why = calls[0]
    assert addr == "203.0.113.7:8333" and score == 10 and reason in why


# ---------------------------------------------------------------------------
# Missing-inputs routing: a child of an in-mempool parent is NOT missing inputs
# ---------------------------------------------------------------------------


class _StubDB:
    def __init__(self, utxos):
        self._utxos = utxos

    def get_utxo(self, txid, vout):
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self._utxos.get(op) for op in outpoints]

    def get_median_time_past(self, height):
        return 1_700_000_000


FUND = b"\x42" * 32
TIP = 500_000  # BIP68 (CSV) active on mainnet


def _pool():
    db = _StubDB({
        (FUND, 0): {"value": 100_000, "script_pubkey": b"\x51",
                    "height": 499_000, "is_coinbase": False},
    })
    v = TransactionValidator(db=db, network="mainnet")
    return Mempool(validator=v, max_size=300_000_000, require_standard=False,
                   full_rbf=True)


def test_child_of_mempool_parent_is_accepted():
    """Core: CCoinsViewMemPool supplies the parent's outputs.  d94041f:
    'Input not found: <parent>:0' and the relayer punished."""
    pool = _pool()
    parent = _tx(FUND, 0, 90_000)
    ok, err = pool.add_transaction(parent, TIP)
    assert ok, err
    child = _tx(parent.get_txid(), 0, 80_000)
    ok, err = pool.add_transaction(child, TIP)
    assert ok, err
    assert child.get_txid() in pool.transactions
    # fee is computed over the mempool coin, not dropped or refused
    assert pool.transactions[child.get_txid()].fee == 10_000


def test_grandchild_chain_is_accepted():
    pool = _pool()
    a = _tx(FUND, 0, 90_000)
    b = _tx(a.get_txid(), 0, 80_000)
    c = _tx(b.get_txid(), 0, 70_000)
    for t in (a, b, c):
        ok, err = pool.add_transaction(t, TIP)
        assert ok, err


def test_child_overspending_mempool_parent_is_consensus_invalid():
    """Negative control for the overlay: the mempool coin's VALUE is checked —
    the view resolves the input, it does not wave the tx through."""
    from ouroboros.tx_reject import (
        TxValidationResult,
        classify_mempool_reject,
    )
    pool = _pool()
    parent = _tx(FUND, 0, 90_000)
    assert pool.add_transaction(parent, TIP)[0]
    child = _tx(parent.get_txid(), 0, 95_000)
    ok, err = pool.add_transaction(child, TIP)
    assert not ok
    assert err.startswith("bad-txns-in-belowout"), err
    assert classify_mempool_reject(err) is TxValidationResult.TX_CONSENSUS


def test_relative_timelock_on_mempool_parent_is_premature():
    """A mempool coin is at height tip+1 (Core MEMPOOL_HEIGHT via
    CalculateLockPointsAtTip): a 1-block relative lock on it cannot be met
    in the next block — premature, not missing, not consensus."""
    from ouroboros.tx_reject import (
        TxValidationResult,
        classify_mempool_reject,
    )
    pool = _pool()
    parent = _tx(FUND, 0, 90_000)
    assert pool.add_transaction(parent, TIP)[0]
    child = _tx(parent.get_txid(), 0, 80_000, seq=1)  # BIP68: 1 block
    ok, err = pool.add_transaction(child, TIP)
    assert not ok
    assert classify_mempool_reject(err) is TxValidationResult.TX_PREMATURE_SPEND


def test_unknown_parent_still_goes_to_orphanage():
    pool = _pool()
    child = _tx(b"\x77" * 32, 0, 1_000)
    ok, err = pool.add_transaction(child, TIP, "198.51.100.1:8333")
    assert not ok and err == "orphan"
    assert pool.orphan_pool.has_wtxid(child.get_wtxid())


def test_rbf_replacement_spending_mempool_parent_counts_its_value():
    """_try_replace_inner summed only chain coins, so an input from an
    in-mempool parent counted 0 and the replacement's fee was understated."""
    fund2 = b"\x43" * 32
    db = _StubDB({
        (FUND, 0): {"value": 100_000, "script_pubkey": b"\x51",
                    "height": 499_000, "is_coinbase": False},
        (fund2, 0): {"value": 100_000, "script_pubkey": b"\x51",
                     "height": 499_000, "is_coinbase": False},
    })
    pool = Mempool(validator=TransactionValidator(db=db, network="mainnet"),
                   max_size=300_000_000, require_standard=False, full_rbf=True)
    parent = _tx(FUND, 0, 90_000)
    assert pool.add_transaction(parent, TIP)[0]

    def spend(value):
        t = Transaction(
            txid=b"", version=2, locktime=0,
            inputs=[TxIn(prev_txid=parent.get_txid(), prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD),
                    TxIn(prev_txid=fund2, prev_vout=0, script_sig=b"",
                         sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=value, script_pubkey=b"\x51")],
        )
        t.txid = _dsha(t.serialize())
        return t

    original = spend(180_000)                 # fee 10,000
    ok, err = pool.add_transaction(original, TIP)
    assert ok, err
    replacement = spend(170_000)              # fee 20,000
    ok, err = pool.add_transaction(replacement, TIP)
    assert ok, err
    assert replacement.get_txid() in pool.transactions
    assert original.get_txid() not in pool.transactions
