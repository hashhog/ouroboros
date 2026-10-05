"""Classify a mempool rejection into Bitcoin Core's ``TxValidationResult``.

The mempool (``Mempool.add_transaction``) reports a rejection as a reason
string.  Whether the peer that relayed the transaction deserves a misbehaviour
score depends on WHY it was rejected, and almost every reason is local policy
or local state rather than proof that the peer is misbehaving:

* Core ``consensus/validation.h`` ``TxValidationResult`` separates
  ``TX_CONSENSUS`` (invalid by consensus) from ``TX_MISSING_INPUTS``,
  ``TX_PREMATURE_SPEND``, ``TX_NOT_STANDARD``, ``TX_INPUTS_NOT_STANDARD``,
  ``TX_WITNESS_MUTATED``, ``TX_CONFLICT``, ``TX_MEMPOOL_POLICY`` and
  ``TX_RECONSIDERABLE``.
* Core up to v27 (``net_processing.cpp`` ``MaybePunishNodeForTx``) punished
  ONLY ``TX_CONSENSUS``; every other result was explicitly unpunished.  The
  reference tree in ``bitcoin-core/`` (post-v28) goes further: tx rejections
  are never punished at all — ``ProcessInvalidTx`` only logs and feeds the
  tx-download manager (orphanage / recent-rejects).

ouroboros keeps the v27 shape: a STRICT allow-list of reasons that are
consensus-invalid regardless of local policy, chain tip or mempool contents.
Anything not on the list — including reasons this module does not recognise
— is never punished.  A peer relaying a child of a transaction we already hold,
a low-fee tx, an RBF attempt or a tx we already know is doing exactly what an
honest Bitcoin Core peer does.
"""

from __future__ import annotations

from enum import Enum


class TxValidationResult(Enum):
    """Mirror of Core ``TxValidationResult`` (consensus/validation.h)."""

    TX_CONSENSUS = "consensus"
    TX_INPUTS_NOT_STANDARD = "inputs-not-standard"
    TX_NOT_STANDARD = "not-standard"
    TX_MISSING_INPUTS = "missing-inputs"
    TX_PREMATURE_SPEND = "premature-spend"
    TX_WITNESS_MUTATED = "witness-mutated"
    TX_WITNESS_STRIPPED = "witness-stripped"
    TX_CONFLICT = "conflict"
    TX_MEMPOOL_POLICY = "mempool-policy"
    TX_RECONSIDERABLE = "reconsiderable"
    TX_INTERNAL = "internal"      # our own fault (DB read error, node halted)
    TX_UNKNOWN = "unknown"        # unrecognised reason: never punished


# Reasons that are consensus-invalid independent of policy, tip and mempool.
# Bare Core tokens only (CheckTransaction / CheckTxInputs / PreChecks
# coinbase), exactly as TransactionValidator / Mempool emit them.
_CONSENSUS_EXACT = frozenset({
    "coinbase",                          # validation.cpp PreChecks TX_CONSENSUS
    # consensus/tx_check.cpp CheckTransaction
    "bad-txns-vin-empty",
    "bad-txns-vout-empty",
    "bad-txns-oversize",
    "bad-txns-vout-negative",
    "bad-txns-vout-toolarge",
    "bad-txns-txouttotal-toolarge",
    "bad-txns-inputs-duplicate",
    "bad-cb-length",
    "bad-txns-prevout-null",
    # consensus/tx_verify.cpp CheckTxInputs
    "bad-txns-inputvalues-outofrange",
    "bad-txns-fee-outofrange",
})
_CONSENSUS_PREFIX = (
    "bad-txns-in-belowout",              # "bad-txns-in-belowout: value in (..)"
)

_MISSING_INPUTS_PREFIX = (
    "orphan",                 # internal control token (stored in orphan pool)
    "missing-inputs",
    "Input not found",        # validator could not resolve a prevout
    "UTXO not found",
)

_CONFLICT_EXACT = frozenset({
    "txn-already-in-mempool",
    "txn-same-nonwitness-data-in-mempool",
    "txn-already-known",
    "Already in orphan pool",
})

_PREMATURE_PREFIX = (
    "non-final",
    "bad-txns-premature-spend-of-coinbase",
    "BIP 68",
    "non-BIP68-final",
)

_NOT_STANDARD_PREFIX = (
    "version", "tx-size", "scriptsig-size", "scriptsig-not-pushonly",
    "scriptpubkey", "datacarrier", "dust", "multi-op-return",
    "bad-txns-too-many-sigops", "bad-txns-nonstandard-inputs",
    "v3 transaction has ephemeral dust", "tx with dust output",
    "ephemeral dust",
)

_MEMPOOL_POLICY_PREFIX = (
    "min relay fee not met", "mempool min fee not met", "mempool full",
    "insufficient fee", "Replacement", "replacement", "Conflicting tx",
    "No conflicts to replace", "too many potential replacements",
    "replacement-adds-unconfirmed", "txn-mempool-conflict",
    "tx would", "too-large-cluster", "Sibling", "Failed after sibling",
    "TRUC", "truc", "v3", "version=3",
)


def classify_mempool_reject(reason: str | None) -> TxValidationResult:
    """Map a ``Mempool.add_transaction`` reason to Core's TxValidationResult."""
    from ouroboros.fatal import is_internal_error_text

    if not reason:
        return TxValidationResult.TX_UNKNOWN
    if is_internal_error_text(reason) or reason == "missing-ancestor-header":
        return TxValidationResult.TX_INTERNAL
    if reason in _CONSENSUS_EXACT or reason.startswith(_CONSENSUS_PREFIX):
        return TxValidationResult.TX_CONSENSUS
    if reason.startswith(_MISSING_INPUTS_PREFIX):
        return TxValidationResult.TX_MISSING_INPUTS
    if reason in _CONFLICT_EXACT:
        return TxValidationResult.TX_CONFLICT
    if reason.startswith(_PREMATURE_PREFIX):
        return TxValidationResult.TX_PREMATURE_SPEND
    if reason == "bad-witness-nonstandard":
        return TxValidationResult.TX_WITNESS_MUTATED
    if reason.startswith(_NOT_STANDARD_PREFIX):
        return TxValidationResult.TX_NOT_STANDARD
    if reason.startswith(_MEMPOOL_POLICY_PREFIX):
        return TxValidationResult.TX_MEMPOOL_POLICY
    # Script failures ("Invalid signature for input N") are verified with
    # STANDARD flags on the mempool path; Core re-runs with the mandatory
    # flags to tell TX_NOT_STANDARD from TX_CONSENSUS (validation.cpp
    # PolicyScriptChecks).  ouroboros does not, so it cannot prove the
    # failure is consensus — unknown, never punished.
    return TxValidationResult.TX_UNKNOWN


def should_punish_tx_reject(result: TxValidationResult) -> bool:
    """Strict allow-list: only consensus-invalid transactions are punished."""
    return result is TxValidationResult.TX_CONSENSUS
