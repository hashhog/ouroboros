"""Recent-rejects filter for relayed transactions (Core ``m_lazy_recent_rejects``).

A transaction the mempool refused is remembered by wtxid until the chain tip
changes, so a peer resending it (or several peers relaying it) does not make
the node re-run full validation, scripts included, every time.

Core (``node/txdownloadman_impl.cpp``):

* ``ReceivedTx`` drops a tx whose wtxid is in ``RecentRejectsFilter`` before
  it reaches ``AcceptToMemoryPool``, and a tx whose wtxid is in
  ``RecentRejectsReconsiderableFilter`` is not submitted on its own again
  (only as part of a 1p1c package, which this node's P2P path does not
  build).  A filtered tx is never punished: the filter can give false
  positives and records policy failures too.
* ``MempoolRejectedTx`` inserts the wtxid: TX_RECONSIDERABLE (the fee floors)
  into the reconsiderable filter, every other result into the rejects
  filter.  TX_MISSING_INPUTS goes to the orphanage instead, and
  TX_WITNESS_STRIPPED is never recorded.  Only the wtxid is recorded (not the
  txid), because a witness can be malleated: a mutated copy has a different
  wtxid, so caching it cannot block the honest version.
* ``ActiveTipChange`` resets both filters: a new tip can make a rejected tx
  valid (``non-final``, a premature coinbase spend, a conflict that was mined
  away, a changed mempool minimum fee).

Differences from Core, all on the side of caching less:

* ouroboros cannot tell a witness-stripped tx from a genuinely bad one (Core
  re-runs the scripts without the witness flags).  A script failure of a tx
  that carries no witness is therefore never recorded: such a tx has
  wtxid == txid, and recording it could block the real, witnessed tx when a
  legacy peer announces it by txid.
* Rejections that come from our own state rather than the tx (a database read
  fault, a halted node, a header still being backfilled) are not recorded.
  The duplicate rejects (already in mempool / orphan pool / chain) are cheap
  and are answered by the mempool and orphan pool themselves.
* The filters are exact bounded sets (oldest entry dropped first) of Core's
  capacity, not rolling bloom filters, so they have no false positives.
"""

from __future__ import annotations

from collections import OrderedDict

from ouroboros.tx_reject import TxValidationResult, classify_mempool_reject

# Core net_processing / txdownloadman: CRollingBloomFilter{120'000, 0.000'001}
# for both m_lazy_recent_rejects and m_lazy_recent_rejects_reconsiderable.
RECENT_REJECTS_CAPACITY = 120_000

# Core TX_RECONSIDERABLE results on the single-transaction path
# (validation.cpp CheckFeeRate, and LimitMempoolSize's "mempool full").
_RECONSIDERABLE_EXACT = frozenset({
    "min relay fee not met",
    "mempool min fee not met",
    "mempool full",
})

# Results that are never recorded: our own state, the orphanage path, and the
# duplicate checks the mempool already answers without validating.
_NEVER_RECORDED = frozenset({
    TxValidationResult.TX_INTERNAL,
    TxValidationResult.TX_MISSING_INPUTS,
    TxValidationResult.TX_CONFLICT,
})


def _is_script_failure(reason: str) -> bool:
    return (
        reason.startswith("Invalid signature for input")
        or "script-verify-flag-failed" in reason
    )


class _BoundedSet:
    """Insertion-ordered set that forgets its oldest entry past *capacity*."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self._items: OrderedDict[bytes, None] = OrderedDict()

    def insert(self, key: bytes) -> None:
        if key in self._items:
            return
        self._items[key] = None
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)

    def __contains__(self, key: object) -> bool:
        return key in self._items

    def __len__(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items.clear()


class RecentRejects:
    """The two Core reject filters, reset whenever the chain tip changes."""

    def __init__(self, capacity: int = RECENT_REJECTS_CAPACITY):
        self.rejects = _BoundedSet(capacity)
        self.reconsiderable = _BoundedSet(capacity)
        self._tip: bytes | None = None

    def tip_changed(self, tip_hash: bytes | None) -> None:
        """Reset both filters if *tip_hash* is not the tip they were filled at
        (Core ``ActiveTipChange``, checked lazily on the next tx)."""
        if tip_hash != self._tip:
            self.rejects.clear()
            self.reconsiderable.clear()
            self._tip = tip_hash

    def contains(self, wtxid: bytes) -> bool:
        """Core ``ReceivedTx``: skip a tx in either filter."""
        return wtxid in self.rejects or wtxid in self.reconsiderable

    def record(self, wtxid: bytes, reason: str | None, has_witness: bool) -> bool:
        """Record a mempool rejection (Core ``MempoolRejectedTx``).

        Returns True when the wtxid was recorded.
        """
        if not reason:
            return False
        if reason in _RECONSIDERABLE_EXACT:
            self.reconsiderable.insert(wtxid)
            return True
        result = classify_mempool_reject(reason)
        if result in _NEVER_RECORDED:
            return False
        if _is_script_failure(reason) and not has_witness:
            # Possibly witness-stripped (Core TX_WITNESS_STRIPPED): never
            # recorded.  See the module docstring.
            return False
        self.rejects.insert(wtxid)
        return True

    def __len__(self) -> int:
        return len(self.rejects) + len(self.reconsiderable)
