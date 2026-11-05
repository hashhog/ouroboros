"""testmempoolaccept judges a coinbase spend at the next block's height.

Core (rpc/mempool.cpp testmempoolaccept -> AcceptToMemoryPool with
test_accept=true; validation.cpp MemPoolAccept::PreChecks ->
Consensus::CheckTxInputs(tx, state, m_view, m_active_chainstate.m_chain.Height() + 1, ...))
checks a mempool candidate as if it were in the block after the tip, the
same height sendrawtransaction uses.  consensus/tx_verify.cpp CheckTxInputs
then refuses a coinbase coin whose depth ``nSpendHeight - coin.nHeight`` is
below COINBASE_MATURITY with reject-reason
``bad-txns-premature-spend-of-coinbase`` and debug
``tried to spend coinbase at depth <d>``; testmempoolaccept prints the
debug string as ``reject-details`` = ``state.ToString()`` =
``"<reason>, <debug>"``.

Core regtest rows: ``(seed|warden)_invalidated_submit/maturity/tip99-accept``.
At tip 99 a spend of the height-1 coinbase is at depth 99: Core refuses it.
ouroboros passed ``tip + 1`` into a mempool that adds one itself, so it
judged the spend at depth 100 and allowed it.

Every test drives ``RPCServer.rpc_testmempoolaccept`` (on master) over the
real ``Mempool`` and the real ``TransactionValidator``.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402
from ouroboros.validation import TransactionValidator  # noqa: E402

OP_TRUE = b"\x51"
COINBASE_TXID = bytes([0x77]) * 32
COINBASE_HEIGHT = 1
COIN_VALUE = 50 * 100_000_000


class _ChainDB:
    """A chain whose tip is ``tip`` and whose only coin is the height-1 coinbase."""

    def __init__(self, tip: int):
        self.tip = tip
        self.coin = {
            "txid": COINBASE_TXID, "vout": 0, "value": COIN_VALUE,
            "script_pubkey": OP_TRUE, "height": COINBASE_HEIGHT,
            "is_coinbase": True,
        }

    def get_utxo(self, txid, vout):
        if (bytes(txid), vout) == (COINBASE_TXID, 0):
            return dict(self.coin)
        return None

    def get_utxo_batch(self, outpoints):
        return [self.get_utxo(t, v) for t, v in outpoints]

    def get_median_time_past(self, height=None):
        return 1_700_000_000

    def get_best_block(self):
        return bytes([self.tip]) * 32, self.tip


def _spend() -> Transaction:
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=COINBASE_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=COIN_VALUE - 10_000, script_pubkey=OP_TRUE)],
    )
    return TxMessage.from_payload(tmp.serialize()).transaction


def _testmempoolaccept(tip: int) -> dict:
    db = _ChainDB(tip)
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))
    tx = _spend()
    [row] = asyncio.run(RPCServer.rpc_testmempoolaccept(rpc, [tx.serialize().hex()]))
    assert row["txid"] == tx.get_txid()[::-1].hex()
    assert not pool.transactions, "test_accept must not add to the pool"
    return row


def test_tip99_coinbase_spend_is_premature():
    row = _testmempoolaccept(tip=99)
    assert row["allowed"] is False
    assert row["reject-reason"] == "bad-txns-premature-spend-of-coinbase"
    assert row["reject-details"] == (
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
    )


def test_tip100_coinbase_spend_is_mature():
    # Negative control: one block later the same spend is at depth 100 and
    # Core allows it, so the fix must not move the boundary the other way.
    row = _testmempoolaccept(tip=100)
    assert row["allowed"] is True, row
    assert "reject-details" not in row


def test_tip98_coinbase_spend_reports_its_depth():
    row = _testmempoolaccept(tip=98)
    assert row["allowed"] is False
    assert row["reject-reason"] == "bad-txns-premature-spend-of-coinbase"
    assert row["reject-details"].endswith("tried to spend coinbase at depth 98")


def test_reject_details_split_follows_core_tostring():
    import ouroboros.rpc as rpc_mod

    _reject_reason_and_details = getattr(rpc_mod, "_reject_reason_and_details", None)
    assert _reject_reason_and_details is not None, "no reason/details split helper"
    assert _reject_reason_and_details(
        "bad-txns-premature-spend-of-coinbase: tried to spend coinbase at depth 7"
    ) == (
        "bad-txns-premature-spend-of-coinbase",
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 7",
    )
    # No debug message: ToString() is the bare reason.
    assert _reject_reason_and_details("txn-already-known") == (
        "txn-already-known", "txn-already-known")
    # Free text is not split.
    assert _reject_reason_and_details("Input not found: ab:0") == (
        "Input not found: ab:0", "Input not found: ab:0")


# --------------------------------------------------------------------------
# The same off-by-one moved IsFinalTx: Core checks a mempool candidate with
# nBlockHeight = tip + 1 (validation.cpp PreChecks -> CheckFinalTxAtTip), so a
# height lock equal to tip + 1 is not final yet and one equal to tip is.
# --------------------------------------------------------------------------

def _locked_spend(locktime: int) -> Transaction:
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=locktime,
        inputs=[TxIn(prev_txid=COINBASE_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFE)],
        outputs=[TxOut(value=COIN_VALUE - 10_000, script_pubkey=OP_TRUE)],
    )
    return TxMessage.from_payload(tmp.serialize()).transaction


def _accept_locked(tip: int, locktime: int) -> dict:
    db = _ChainDB(tip)
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))
    [row] = asyncio.run(RPCServer.rpc_testmempoolaccept(
        rpc, [_locked_spend(locktime).serialize().hex()]))
    return row


def test_height_locktime_of_next_block_is_not_final():
    row = _accept_locked(tip=200, locktime=201)
    assert row["allowed"] is False
    assert row["reject-reason"] == "non-final"


def test_height_locktime_of_tip_is_final():
    row = _accept_locked(tip=200, locktime=200)
    assert row["allowed"] is True, row
