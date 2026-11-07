"""Context-free CheckBlock reject token (Bitcoin Core validation.cpp CheckBlock).

Core's ``ChainstateManager::ProcessNewBlock`` runs ``CheckBlock`` BEFORE
``AcceptBlock`` (validation.cpp:4416-4419), and the block-index lookups that
answer ``prev-blk-not-found`` / ``bad-prevblk`` / ``duplicate-invalid`` live in
``AcceptBlockHeader`` (validation.cpp:4190-4222), inside AcceptBlock.  So a
block that fails a context-free check is reported by THAT check's token even
when its parent is unknown or failed: a bad-merkle-root block on an
invalidated parent is ``bad-txnmrklroot``, not ``bad-prevblk``.

``check_block_reject_token`` returns the first token Core's CheckBlock
(validation.cpp:3918-3983) would emit for *block*, or ``None`` when every gate
it evaluates passes.  It is used only on submitblock paths that reject the
block anyway (unknown or failed parent, failed block), so it can change the
reported reason but never the verdict.

Gates, in Core's order:

  1. CheckBlockHeader -> CheckProofOfWork               "high-hash"
  2. CheckMerkleRoot (BlockMerkleRoot + mutation)         "bad-txnmrklroot" /
                                                          "bad-txns-duplicate"
  3. size limits                                          "bad-blk-length"
  4. coinbase position                                    "bad-cb-missing" /
                                                          "bad-cb-multiple"
  5. CheckTransaction on every tx                         the tx's own token
  6. legacy sigop count                                   "bad-blk-sigops"

Not evaluated: the signet block solution (signet only, needs the signet
challenge), which keeps the caller's previous token for such a block.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from ouroboros.p2p_messages import encode_varint
from ouroboros.validation import (
    MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT,
    WITNESS_SCALE_FACTOR,
    _bits_to_target_checked,
    _count_legacy_sigops,
    _get_pow_limit,
)


def _dsha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_merkle_root(hashes: list[bytes]) -> tuple[bytes, bool]:
    """Core consensus/merkle.cpp ``ComputeMerkleRoot`` with its mutation flag.

    ``mutated`` is set when two ADJACENT hashes at any level are equal (the
    CVE-2012-2459 duplication), checked before the odd-count padding, exactly
    as Core does; the padding itself never sets it.
    """
    level = [bytes(h) for h in hashes]
    mutation = False
    while len(level) > 1:
        for pos in range(0, len(level) - 1, 2):
            if level[pos] == level[pos + 1]:
                mutation = True
        if len(level) & 1:
            level.append(level[-1])
        level = [_dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    if not level:
        return bytes(32), mutation
    return level[0], mutation


def _check_proof_of_work(block_hash: bytes, bits: int, pow_limit: int) -> bool:
    """Core pow.cpp ``CheckProofOfWorkImpl``: decode nBits, refuse a negative,
    zero or overflowing target or one above powLimit, then hash <= target."""
    try:
        target, negative, overflow = _bits_to_target_checked(int(bits))
    except Exception:
        return False
    if negative or overflow or target == 0 or target > pow_limit:
        return False
    return int.from_bytes(bytes(block_hash), "little") <= target


def _stripped_size(block) -> int:
    """``GetSerializeSize(TX_NO_WITNESS(block))``: header + count + base txs."""
    return 80 + len(encode_varint(len(block.transactions))) + sum(
        len(tx.serialize()) for tx in block.transactions
    )


def check_block_reject_token(
    block,
    block_hash: bytes,
    network: str,
    check_transaction: Callable | None = None,
) -> str | None:
    """First reject token of Core's CheckBlock for *block*, else ``None``.

    *block* is a decoded ``ouroboros.database.Block``; *block_hash* its
    double-SHA256 header hash (internal byte order).  *check_transaction* is
    Core's CheckTransaction for one tx, returning its reject token or
    ``None`` (``TransactionValidator._check_structure``); when absent, gate 5
    is skipped.
    """
    # 1. CheckBlockHeader -> CheckProofOfWork (validation.cpp CheckBlockHeader).
    if not _check_proof_of_work(block_hash, block.bits, _get_pow_limit(network)):
        return "high-hash"

    # 2. CheckMerkleRoot (validation.cpp CheckMerkleRoot).
    root, mutated = compute_merkle_root([tx.get_txid() for tx in block.transactions])
    if bytes(block.merkle_root) != root:
        return "bad-txnmrklroot"
    if mutated:
        return "bad-txns-duplicate"

    # 3. Size limits (validation.cpp:3947-3948).
    txs = block.transactions
    if (not txs
            or len(txs) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
            or _stripped_size(block) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT):
        return "bad-blk-length"

    # 4. Coinbase position (validation.cpp:3951-3955).
    if not txs[0].is_coinbase:
        return "bad-cb-missing"
    for tx in txs[1:]:
        if tx.is_coinbase:
            return "bad-cb-multiple"

    # 5. CheckTransaction (validation.cpp:3959-3968).
    if check_transaction is not None:
        for tx in txs:
            token = check_transaction(tx)
            if token:
                return token

    # 6. Legacy sigops (validation.cpp:3971-3977, GetLegacySigOpCount).
    sigops = 0
    for tx in txs:
        for txin in tx.inputs:
            sigops += _count_legacy_sigops(txin.script_sig)
        for txout in tx.outputs:
            sigops += _count_legacy_sigops(txout.script_pubkey)
    if sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST:
        return "bad-blk-sigops"

    return None
