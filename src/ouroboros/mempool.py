"""
Transaction mempool management.

This module implements the unconfirmed transaction pool with fee rate
sorting, double spend detection, size management, ancestor/descendant
limits, and standardness checks.
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
import os
import random
import struct
import threading
import time
import logging

from ouroboros.database import Transaction
from ouroboros.validation import TransactionValidator

logger = logging.getLogger(__name__)

OutPoint = Tuple[bytes, int]

# Policy constants
MAX_STANDARD_TX_WEIGHT = 400_000
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
MAX_ANCESTOR_COUNT = 25
MAX_DESCENDANT_COUNT = 25
MAX_ANCESTOR_SIZE_KVB = 101
MAX_DESCENDANT_SIZE_KVB = 101
DUST_RELAY_TX_FEE = 3000  # sat/kB
DEFAULT_MIN_RELAY_TX_FEE = 1000  # sat/kvB
MEMPOOL_EXPIRY_HOURS = 336  # 14 days
TX_MAX_STANDARD_VERSION = 3

# TRUC (v3 transaction) policy constants (Bitcoin Core policy/truc_policy.cpp)
TX_V3_MAX_VSIZE = 10_000  # max vsize for a v3 child of an unconfirmed v3 parent
TX_V3_ANCESTOR_LIMIT = 2  # v3 tx may have at most 1 unconfirmed ancestor (self + 1)
TX_V3_DESCENDANT_LIMIT = 2  # v3 tx may have at most 1 unconfirmed descendant (self + 1)

# Package validation limits (BIP 331)
MAX_PACKAGE_COUNT = 25
MAX_PACKAGE_WEIGHT = 404_000  # weight units


def _get_dust_threshold(script_pubkey: bytes) -> int:
    # P2PKH/P2SH cost: 34 + 148 = 182 bytes
    # P2WPKH cost: 31 + 68 = 99 bytes (roughly)
    # P2WSH cost: 43 + 68 = 111 bytes
    # P2TR cost: 43 + 57.5 = 100.5 bytes
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00:
        n_size = 99  # P2WPKH
    elif len(script_pubkey) == 34 and script_pubkey[0] in (0x00, 0x51):
        n_size = 110  # P2WSH or P2TR
    elif len(script_pubkey) == 23 and script_pubkey[0] == 0xa9:
        n_size = 182  # P2SH
    else:
        n_size = 182  # P2PKH and others
    return (n_size * DUST_RELAY_TX_FEE) // 1000


def _has_ephemeral_dust(tx: Transaction) -> List[int]:
    dust_indices: List[int] = []
    for idx, out in enumerate(tx.outputs):
        if out.script_pubkey and out.script_pubkey[0] == 0x6a:
            continue  # OP_RETURN is never dust
        threshold = _get_dust_threshold(out.script_pubkey)
        if out.value < threshold:
            dust_indices.append(idx)
    return dust_indices


def _is_standard_tx(tx: Transaction) -> Tuple[bool, str]:
    if tx.version < 1 or tx.version > TX_MAX_STANDARD_VERSION:
        return False, f"Non-standard version: {tx.version}"

    tx_bytes = tx.serialize()
    tx_size = len(tx_bytes)
    # Weight approximation: non-witness size * 3 + total size
    tx_weight = tx_size * 4  # conservative upper bound
    if tx_weight > MAX_STANDARD_TX_WEIGHT:
        return False, f"Transaction weight {tx_weight} exceeds {MAX_STANDARD_TX_WEIGHT}"

    if tx_size < MIN_STANDARD_TX_NONWITNESS_SIZE:
        return False, f"Transaction too small: {tx_size} < {MIN_STANDARD_TX_NONWITNESS_SIZE}"

    # Check for dust outputs — v3 transactions use ephemeral dust rules
    # instead of the normal dust rejection (checked later in package
    # validation or individual-submission rejection).
    if tx.version != 3:
        dust_indices = _has_ephemeral_dust(tx)
        if dust_indices:
            return False, f"Transaction has {len(dust_indices)} dust output(s)"

    return True, ""


@dataclass
class MempoolEntry:
    """Entry in the mempool"""
    tx: Transaction
    fee: int
    fee_rate: float  # sat/vbyte
    size: int
    time_added: float
    height_added: int
    ancestor_count: int = 1
    ancestor_size: int = 0
    descendant_count: int = 1
    descendant_size: int = 0


# Orphan transaction pool
MAX_ORPHAN_TRANSACTIONS = 100
ORPHAN_EXPIRY_SECONDS = 20 * 60  # 20 minutes


class OrphanPool:
    """Pool of transactions whose parent outputs are not yet available.

    When a transaction references UTXOs that are neither in the chain nor
    in the mempool, it is stored here until the missing parents arrive.
    """

    def __init__(self):
        # orphan txid → (Transaction, expiry_time, set of missing parent txids)
        self.orphans: Dict[bytes, Tuple[Transaction, float, Set[bytes]]] = {}
        # missing parent txid → set of orphan txids waiting on it
        self.by_parent: Dict[bytes, Set[bytes]] = {}

    def add(self, tx: Transaction, missing_parents: Set[bytes]) -> bool:
        """Add an orphan transaction.  Returns True if added."""
        txid = tx.get_txid()
        if txid in self.orphans:
            return False
        if len(self.orphans) >= MAX_ORPHAN_TRANSACTIONS:
            self._evict_random()
        expiry = time.time() + ORPHAN_EXPIRY_SECONDS
        self.orphans[txid] = (tx, expiry, missing_parents)
        for parent in missing_parents:
            self.by_parent.setdefault(parent, set()).add(txid)
        logger.debug(
            f"Added orphan tx {txid.hex()[:16]}... "
            f"(missing {len(missing_parents)} parent(s), "
            f"pool size {len(self.orphans)})"
        )
        return True

    def remove(self, txid: bytes) -> None:
        """Remove an orphan by txid."""
        entry = self.orphans.pop(txid, None)
        if entry is None:
            return
        _, _, missing = entry
        for parent in missing:
            s = self.by_parent.get(parent)
            if s:
                s.discard(txid)
                if not s:
                    del self.by_parent[parent]

    def get_orphans_for_parent(self, parent_txid: bytes) -> List[Transaction]:
        """Return orphan txs that are waiting on *parent_txid*."""
        orphan_ids = self.by_parent.get(parent_txid, set())
        result = []
        for oid in list(orphan_ids):
            entry = self.orphans.get(oid)
            if entry:
                result.append(entry[0])
        return result

    def has(self, txid: bytes) -> bool:
        return txid in self.orphans

    def expire(self) -> int:
        """Remove expired orphans.  Returns count removed."""
        now = time.time()
        expired = [
            txid for txid, (_, exp, _) in self.orphans.items()
            if now >= exp
        ]
        for txid in expired:
            self.remove(txid)
        if expired:
            logger.debug(f"Expired {len(expired)} orphan transaction(s)")
        return len(expired)

    def size(self) -> int:
        return len(self.orphans)

    def _evict_random(self) -> None:
        if not self.orphans:
            return
        victim = random.choice(list(self.orphans))
        logger.debug(f"Evicting random orphan {victim.hex()[:16]}...")
        self.remove(victim)


class Mempool:
    """Unconfirmed transaction pool"""
    
    def __init__(
        self,
        validator: TransactionValidator,
        max_size: int = 300_000_000,  # 300 MB
        require_standard: bool = True,
    ):
        """Initialize mempool."""
        self.validator = validator
        self.max_size = max_size
        self.require_standard = require_standard
        
        self.transactions: Dict[bytes, MempoolEntry] = {}  # txid -> entry
        self.spent_outputs: Set[OutPoint] = set()
        
        # Sorted by fee rate (for mining)
        self.by_fee_rate: List[bytes] = []  # txids sorted by fee rate (lowest first)
        
        # Tracking
        self.current_size = 0  # bytes

        # Reentrant lock for snapshot isolation (e.g. getblocktemplate).
        # RLock because _resolve_orphans -> add_transaction recurses.
        self._lock = threading.RLock()

        # Orphan transaction pool
        self.orphan_pool = OrphanPool()
    
    def snapshot(self) -> Tuple[List[bytes], Dict[bytes, "MempoolEntry"]]:
        """Take a consistent snapshot of the mempool for template construction.

        Returns a copy of (by_fee_rate, transactions) under the lock so that
        concurrent mutations cannot produce an inconsistent view.
        """
        with self._lock:
            fee_rate_copy = list(self.by_fee_rate)
            txs_copy = dict(self.transactions)
        return fee_rate_copy, txs_copy

    def add_transaction(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        """Validate and add *tx* to the mempool at *height*; returns ``(ok, error_message)``."""
        with self._lock:
            return self._add_transaction_inner(tx, height)

    def _add_transaction_inner(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        """Unlocked implementation of add_transaction."""
        txid = tx.get_txid()

        # Check if already in mempool
        if txid in self.transactions:
            return False, "Already in mempool"

        # Already known as orphan
        if self.orphan_pool.has(txid):
            return False, "Already in orphan pool"

        # Standardness checks (policy, not consensus)
        if self.require_standard:
            is_std, reason = _is_standard_tx(tx)
            if not is_std:
                return False, f"Non-standard transaction: {reason}"

        # Ephemeral dust: reject v3 txs with dust when submitted
        # individually (ephemeral dust is only valid inside packages).
        if tx.version == 3:
            dust_indices = _has_ephemeral_dust(tx)
            if dust_indices:
                return False, (
                    f"v3 transaction has ephemeral dust output(s) at "
                    f"index(es) {dust_indices} — must be submitted in a package"
                )

        # Check for missing parent transactions — store as orphan
        missing_parents: Set[bytes] = set()
        for tx_in in tx.inputs:
            parent_txid = tx_in.prev_txid
            # Parent available if UTXO exists in chain or parent is in mempool
            utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo is None and parent_txid not in self.transactions:
                missing_parents.add(parent_txid)
        if missing_parents:
            self.orphan_pool.add(tx, missing_parents)
            return False, "orphan"

        # Validate transaction (consensus)
        valid, error = self.validator.validate_transaction(tx, height)
        if not valid:
            return False, error
        
        # Check for conflicts (double spends) — attempt BIP 125 RBF
        has_conflict = any(
            (tx_in.prev_txid, tx_in.prev_vout) in self.spent_outputs
            for tx_in in tx.inputs
        )
        if has_conflict:
            return self.try_replace(tx, height)

        # TRUC (v3 transaction) policy checks — must come before general
        # ancestor/descendant limits.
        if tx.version == 3:
            truc_ok, truc_err = self._check_v3_policy(tx)
            if not truc_ok:
                return False, truc_err

        # For any existing v3 parent in the mempool: enforce that the
        # v3 parent gets at most one unconfirmed child.  If it already
        # has a child, redirect to replacement.
        for tx_in in tx.inputs:
            parent_entry = self.transactions.get(tx_in.prev_txid)
            if parent_entry is not None and parent_entry.tx.version == 3:
                # Check if this v3 parent already has an unconfirmed child
                existing_children = self._get_v3_children(tx_in.prev_txid)
                if existing_children:
                    # The only way to add another child is via replacement
                    return self.try_replace(tx, height)

        # Ancestor/descendant limits
        ancestors = self._get_ancestors(tx)
        if len(ancestors) + 1 > MAX_ANCESTOR_COUNT:
            return False, (
                f"Too many ancestors: {len(ancestors) + 1} > {MAX_ANCESTOR_COUNT}")
        ancestor_size = sum(self.transactions[a].size for a in ancestors if a in self.transactions)  # TODO: this could be cached
        tx_size = len(tx.serialize())
        if (ancestor_size + tx_size) // 1000 > MAX_ANCESTOR_SIZE_KVB:
            return False, "Ancestor size limit exceeded"

        for a_txid in ancestors:
            if a_txid in self.transactions:
                entry = self.transactions[a_txid]
                if entry.descendant_count + 1 > MAX_DESCENDANT_COUNT:
                    return False, (
                        f"Too many descendants for ancestor {a_txid.hex()[:16]}...")
        
        # Check mempool size
        if self.current_size + tx_size > self.max_size:
            self._evict_low_fee_txs(tx_size)
        
        # Calculate fee
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo:
                total_input += utxo['value']
            else:
                return False, f"UTXO not found: {tx_in.prev_txid.hex()[:16]}...:{tx_in.prev_vout}"
        
        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output
        
        if fee < 0:
            return False, "Negative fee"
        
        fee_rate = fee / tx_size if tx_size > 0 else 0
        # print(f'fee_rate={fee_rate}, target={min_relay}')

        # Minimum relay fee
        min_relay = (tx_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        if fee < min_relay:
            return False, "Below minimum relay fee: %d < %d" % (fee, min_relay)
        
        # Add to mempool
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee_rate,
            size=tx_size,
            time_added=time.time(),
            height_added=height,
            ancestor_count=len(ancestors) + 1,
            ancestor_size=ancestor_size + tx_size,
        )
        
        self.transactions[txid] = entry
        self.current_size += tx_size
        
        # Track spent outputs
        for tx_in in tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            self.spent_outputs.add(outpoint)

        # Update ancestor descendant counts
        for a_txid in ancestors:
            if a_txid in self.transactions:
                self.transactions[a_txid].descendant_count += 1
                self.transactions[a_txid].descendant_size += tx_size
        
        # Insert sorted by fee rate
        self._insert_sorted_by_fee_rate(txid, fee_rate)
        
        logger.info(
            f"Added transaction {txid.hex()[:16]}... to mempool "
            f"(fee: {fee}, rate: {fee_rate:.2f} sat/vbyte)"
        )

        # Try to resolve orphans that were waiting on this transaction
        self._resolve_orphans(txid, height)

        return True, ""

    def _get_ancestors(self, tx: Transaction) -> Set[bytes]:
        result: Set[bytes] = set()
        queue = []
        for inp in tx.inputs:
            if inp.prev_txid in self.transactions:
                queue.append(inp.prev_txid)
                result.add(inp.prev_txid)
        while queue:
            parent = queue.pop()
            entry = self.transactions.get(parent)
            if entry is None:
                continue
            for inp in entry.tx.inputs:
                if inp.prev_txid in self.transactions and inp.prev_txid not in result:
                    result.add(inp.prev_txid)
                    queue.append(inp.prev_txid)
        return result

    # --- TRUC (v3) helpers ---

    def _check_v3_policy(self, tx: Transaction) -> Tuple[bool, str]:
        """Enforce TRUC policy for a v3 transaction being added."""
        ancestors = self._get_ancestors(tx)

        # Rule 1: at most 1 unconfirmed ancestor
        if len(ancestors) + 1 > TX_V3_ANCESTOR_LIMIT:
            return False, (
                f"TRUC (v3) tx exceeds unconfirmed ancestor limit: "
                f"{len(ancestors) + 1} > {TX_V3_ANCESTOR_LIMIT}"
            )

        # Rules 2 & 3: per-parent checks
        for inp in tx.inputs:
            parent_entry = self.transactions.get(inp.prev_txid)
            if parent_entry is None:
                continue  # parent is confirmed

            # Rule 2: v3 parent must not already have an unconfirmed child
            if parent_entry.tx.version == 3:
                existing_children = self._get_v3_children(inp.prev_txid)
                if existing_children:
                    return False, (
                        f"TRUC (v3) parent {inp.prev_txid.hex()[:16]}... "
                        f"already has an unconfirmed child"
                    )

                # Rule 3: child vsize limit when parent is v3
                tx_vsize = tx.get_vsize() if hasattr(tx, 'get_vsize') else len(tx.serialize())
                if tx_vsize > TX_V3_MAX_VSIZE:
                    return False, (
                        f"TRUC (v3) child vsize {tx_vsize} exceeds "
                        f"{TX_V3_MAX_VSIZE} limit for v3 parent"
                    )

        return True, ""

    def _get_v3_children(self, parent_txid: bytes) -> List[bytes]:
        children: List[bytes] = []
        for child_txid, child_entry in self.transactions.items():
            for inp in child_entry.tx.inputs:
                if inp.prev_txid == parent_txid:
                    children.append(child_txid)
                    break
        return children

    def _recalculate_ancestors(self, txid: bytes) -> None:
        entry = self.transactions.get(txid)
        if entry is None:
            return
        ancestors = self._get_ancestors(entry.tx)
        entry.ancestor_count = len(ancestors) + 1
        entry.ancestor_size = (
            sum(self.transactions[a].size for a in ancestors if a in self.transactions)
            + entry.size
        )

    def _update_descendants_after_removal(self, removed_txid: bytes) -> None:
        """After removing *removed_txid*, fix ancestor/descendant counts."""
        removed_entry_size = 0
        # We need the removed entry's info, but it's already deleted.
        # Instead, find descendants by scanning the mempool for any tx
        # that has removed_txid in its ancestor chain.  Since we already
        # deleted the entry, _get_ancestors won't include it, but its
        # former descendants still reference it as a parent input — they
        # now have fewer ancestors.

        # Find direct children (txs that spent an output of removed_txid)
        children: Set[bytes] = set()
        for child_txid, child_entry in self.transactions.items():
            for inp in child_entry.tx.inputs:
                if inp.prev_txid == removed_txid:
                    children.add(child_txid)
                    break

        # Collect all descendants of removed tx (via children)
        all_desc: Set[bytes] = set()
        queue = list(children)
        while queue:
            t = queue.pop()
            if t in all_desc:
                continue
            all_desc.add(t)
            for child_txid, child_entry in self.transactions.items():
                if child_txid in all_desc:
                    continue
                for inp in child_entry.tx.inputs:
                    if inp.prev_txid == t:
                        queue.append(child_txid)
                        break

        # Recalculate ancestor counts for all affected descendants
        for desc_txid in all_desc:
            self._recalculate_ancestors(desc_txid)

        # Decrement descendant counts for ancestors of the removed tx.
        # Since the removed tx is gone, we find its former ancestors by
        # looking at ancestors of its direct children (minus the children
        # themselves).  A simpler approach: for each remaining tx, if
        # removed_txid was in its descendant set, decrement.
        # But we don't track that directly.  Instead, walk up from each
        # child to recalculate descendant counts for all ancestors.
        affected_ancestors: Set[bytes] = set()
        for child_txid in children:
            affected_ancestors |= self._get_ancestors(
                self.transactions[child_txid].tx
            )
        # Also include ancestors that aren't parents of children
        # (they lost the removed tx as a descendant)
        # Rebuild descendant counts for affected ancestors
        for anc_txid in affected_ancestors:
            if anc_txid in self.transactions:
                descs = self._collect_descendants(anc_txid)
                descs.discard(anc_txid)  # don't count self
                anc_entry = self.transactions[anc_txid]
                anc_entry.descendant_count = len(descs) + 1  # +1 for self
                anc_entry.descendant_size = (
                    anc_entry.size
                    + sum(
                        self.transactions[d].size
                        for d in descs
                        if d in self.transactions
                    )
                )

    def _resolve_orphans(self, parent_txid: bytes, height: int) -> int:
        accepted = 0
        work_queue = [parent_txid]

        while work_queue:
            ptxid = work_queue.pop(0)
            candidates = self.orphan_pool.get_orphans_for_parent(ptxid)
            for orphan_tx in candidates:
                orphan_id = orphan_tx.get_txid()
                # Remove from orphan pool first so add_transaction
                # doesn't see it as "already in orphan pool"
                self.orphan_pool.remove(orphan_id)
                ok, err = self.add_transaction(orphan_tx, height)
                if ok:
                    accepted += 1
                    # This newly-accepted tx may unblock more orphans
                    work_queue.append(orphan_id)
                    logger.info(
                        f"Resolved orphan {orphan_id.hex()[:16]}... "
                        f"(parent {ptxid.hex()[:16]}...)"
                    )
                # If it fails for a non-orphan reason, it stays removed

        return accepted

    def expire_old_transactions(self, current_time: Optional[float] = None) -> int:
        """Remove transactions that have been in the mempool too long."""
        with self._lock:
            return self._expire_old_transactions_inner(current_time)

    def _expire_old_transactions_inner(self, current_time: Optional[float] = None) -> int:
        now = current_time or time.time()
        cutoff = now - (MEMPOOL_EXPIRY_HOURS * 3600)
        expired = [
            txid for txid, entry in self.transactions.items()
            if entry.time_added < cutoff
        ]
        for txid in expired:
            self.remove_transaction(txid)
        if expired:
            logger.info(f"Expired {len(expired)} old mempool transactions")

        # Also expire old orphans
        self.orphan_pool.expire()

        return len(expired)

    def remove_transaction(self, txid: bytes, _skip_recount: bool = False):
        """
        Remove transaction from mempool.

        Args:
            txid: Transaction ID to remove
            _skip_recount: Internal flag — skip ancestor/descendant
                recalculation (used during batch removals that do a
                single recalculation pass afterward).
        """
        with self._lock:
            self._remove_transaction_inner(txid, _skip_recount)

    def _remove_transaction_inner(self, txid: bytes, _skip_recount: bool = False):
        if txid not in self.transactions:
            return

        entry = self.transactions[txid]
        self.current_size -= entry.size

        # Remove spent outputs
        for tx_in in entry.tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            self.spent_outputs.discard(outpoint)

        # Remove from sorted list
        if txid in self.by_fee_rate:
            self.by_fee_rate.remove(txid)

        del self.transactions[txid]
        logger.debug(f"Removed transaction {txid.hex()[:16]}... from mempool")

        if not _skip_recount:
            self._update_descendants_after_removal(txid)
    
    def remove_block_transactions(self, block):
        """
        Remove transactions from mempool that are in a block.

        Args:
            block: Block containing transactions to remove
        """
        with self._lock:
            self._remove_block_transactions_inner(block)

    def _remove_block_transactions_inner(self, block):
        removed_ids: List[bytes] = []
        for tx in block.transactions:
            if not tx.is_coinbase:
                txid = tx.get_txid()
                if txid in self.transactions:
                    self.remove_transaction(txid, _skip_recount=True)
                    removed_ids.append(txid)

        # Single-pass recount for all remaining affected transactions
        if removed_ids:
            # Collect all remaining txs and recalculate their counts
            for txid in list(self.transactions):
                self._recalculate_ancestors(txid)
            # Rebuild descendant counts from scratch (more efficient for
            # batch removals than per-tx updates)
            for txid, entry in self.transactions.items():
                descs = self._collect_descendants(txid)
                descs.discard(txid)
                entry.descendant_count = len(descs) + 1
                entry.descendant_size = entry.size + sum(
                    self.transactions[d].size
                    for d in descs if d in self.transactions
                )
            logger.info(
                f"Removed {len(removed_ids)} transactions from mempool "
                f"(included in block)"
            )
    
    def get_transaction(self, txid: bytes) -> Optional[Transaction]:
        """
        Get transaction from mempool.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Transaction or None if not found
        """
        entry = self.transactions.get(txid)
        return entry.tx if entry else None
    
    def get_all_transactions(self) -> List[Transaction]:
        """
        Get all transactions in mempool.

        Returns:
            List of all transactions
        """
        txs = [entry.tx for entry in self.transactions.values()]
        return txs
    
    def get_transactions_by_fee_rate(self, limit: Optional[int] = None) -> List[Transaction]:
        """
        Get transactions sorted by fee rate (highest first).
        
        Args:
            limit: Maximum number of transactions to return
            
        Returns:
            List of transactions sorted by fee rate (highest first)
        """
        # by_fee_rate is sorted lowest to highest, so we reverse it
        txids = self.by_fee_rate[-limit:] if limit else self.by_fee_rate
        return [self.transactions[txid].tx for txid in reversed(txids)]
    
    def get_mempool_info(self) -> Dict:
        """
        Get mempool statistics.
        
        Returns:
            Dictionary with mempool statistics
        """
        if not self.transactions:
            return {
                'size': 0,
                'bytes': 0,
                'max_size': self.max_size,
                'min_fee_rate': 0,
                'max_fee_rate': 0,
                'avg_fee_rate': 0,
            }
        
        fee_rates = [entry.fee_rate for entry in self.transactions.values()]
        
        return {
            'size': len(self.transactions),
            'bytes': self.current_size,
            'max_size': self.max_size,
            'min_fee_rate': min(fee_rates),
            'max_fee_rate': max(fee_rates),
            'avg_fee_rate': sum(fee_rates) / len(fee_rates),
            'orphan_count': self.orphan_pool.size(),
        }
    
    # BIP 125 Replace-By-Fee #

    INCREMENTAL_RELAY_FEE = 1000  # sat/kvB
    MAX_REPLACEMENT_EVICTIONS = 100

    def _find_conflicts(self, tx: Transaction) -> Set[bytes]:
        conflicts: Set[bytes] = set()
        for tx_in in tx.inputs:
            op: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            if op in self.spent_outputs:
                for txid, entry in self.transactions.items():
                    for existing_in in entry.tx.inputs:
                        if (existing_in.prev_txid, existing_in.prev_vout) == op:
                            conflicts.add(txid)
        return conflicts

    def _collect_descendants(self, txid: bytes) -> Set[bytes]:
        result: Set[bytes] = {txid}
        queue = [txid]
        while queue:
            parent = queue.pop()
            for child_txid, child_entry in self.transactions.items():
                if child_txid in result:
                    continue
                for inp in child_entry.tx.inputs:
                    if inp.prev_txid == parent:
                        result.add(child_txid)
                        queue.append(child_txid)
                        break
        return result

    def try_replace(
        self, new_tx: Transaction, height: int
    ) -> Tuple[bool, str]:
        """
        BIP 125 Replace-By-Fee.

        Rules (following bitcoin/src/policy/rbf.cpp):
        1. Every directly-conflicting tx must signal replaceability
           (at least one input with sequence < 0xfffffffe).
        2. The new tx may not spend any *new* unconfirmed inputs that
           the original transactions did not already spend.
        3. Total evictions (conflicts + descendants) <= 100.
        4. New tx fee must strictly exceed the sum of all evicted fees.
        5. New tx fee must also cover the incremental relay cost.

        Returns (success, error_message).  On success the conflicts
        (and their descendants) are removed and the new tx is added.
        """
        with self._lock:
            return self._try_replace_inner(new_tx, height)

    def _try_replace_inner(
        self, new_tx: Transaction, height: int
    ) -> Tuple[bool, str]:
        """Unlocked implementation of try_replace."""
        conflicts = self._find_conflicts(new_tx)
        if not conflicts:
            return False, "No conflicts to replace"

        # TRUC (v3) replacement constraints
        if new_tx.version == 3:
            # The replacement itself must obey v3 ancestor limits.
            # After evicting conflicts we should end up with ≤ 1
            # unconfirmed ancestor.  Pre-check: count unconfirmed
            # parents that are NOT being evicted.
            remaining_ancestors: Set[bytes] = set()
            for inp in new_tx.inputs:
                if inp.prev_txid in self.transactions and inp.prev_txid not in conflicts:
                    remaining_ancestors.add(inp.prev_txid)
                    # Also walk up the ancestor chain
                    parent_entry = self.transactions.get(inp.prev_txid)
                    if parent_entry:
                        for a in self._get_ancestors(parent_entry.tx):
                            if a not in conflicts:
                                remaining_ancestors.add(a)
            if len(remaining_ancestors) + 1 > TX_V3_ANCESTOR_LIMIT:
                return False, (
                    f"TRUC (v3) replacement exceeds unconfirmed ancestor "
                    f"limit: {len(remaining_ancestors) + 1} > "
                    f"{TX_V3_ANCESTOR_LIMIT}"
                )

            # If replacing a child of a v3 parent, the new child vsize
            # must still be ≤ TX_V3_MAX_VSIZE.
            for inp in new_tx.inputs:
                parent_entry = self.transactions.get(inp.prev_txid)
                if parent_entry is not None and parent_entry.tx.version == 3:
                    tx_vsize = (
                        new_tx.get_vsize()
                        if hasattr(new_tx, 'get_vsize')
                        else len(new_tx.serialize())
                    )
                    if tx_vsize > TX_V3_MAX_VSIZE:
                        return False, (
                            f"TRUC (v3) replacement child vsize {tx_vsize} "
                            f"exceeds {TX_V3_MAX_VSIZE} limit"
                        )

        # Rule 1: all direct conflicts must signal replaceability
        for c_txid in conflicts:
            c_entry = self.transactions[c_txid]
            if not any(inp.sequence < 0xFFFFFFFE for inp in c_entry.tx.inputs):
                return False, "Conflicting tx does not signal replaceability"

        # Gather full eviction set (conflicts + descendants)
        to_evict: Set[bytes] = set()
        for c_txid in conflicts:
            to_evict |= self._collect_descendants(c_txid)

        # Rule 3: eviction count limit
        if len(to_evict) > self.MAX_REPLACEMENT_EVICTIONS:
            return False, (
                f"Replacement would evict {len(to_evict)} txs "
                f"(max {self.MAX_REPLACEMENT_EVICTIONS})"
            )

        # Rule 2: new tx must not introduce new unconfirmed inputs
        old_unconfirmed: Set[OutPoint] = set()
        for txid in to_evict:
            entry = self.transactions[txid]
            for inp in entry.tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                if inp.prev_txid in self.transactions:
                    old_unconfirmed.add(op)
        for inp in new_tx.inputs:
            op = (inp.prev_txid, inp.prev_vout)
            if inp.prev_txid in self.transactions and op not in old_unconfirmed:
                return False, "Replacement introduces new unconfirmed input"

        # Calculate new tx fee
        new_size = len(new_tx.serialize())
        total_input = 0
        for inp in new_tx.inputs:
            utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo:
                total_input += utxo['value']
        total_output = sum(out.value for out in new_tx.outputs)
        new_fee = total_input - total_output

        # Sum of fees from all evicted transactions
        old_fees = sum(self.transactions[t].fee for t in to_evict)

        # Rule 4: strictly higher fee
        if new_fee <= old_fees:
            return False, (
                f"Replacement fee {new_fee} does not exceed "
                f"evicted fees {old_fees}"
            )

        # Rule 5: covers incremental relay cost
        if new_fee < old_fees + self.INCREMENTAL_RELAY_FEE:
            return False, "Replacement does not cover incremental relay fee"

        # All checks passed — evict and add (skip per-removal recount)
        evicted_ids = set(to_evict)
        for txid in to_evict:
            self.remove_transaction(txid, _skip_recount=True)

        new_fee_rate = new_fee / new_size if new_size > 0 else 0
        new_txid = new_tx.get_txid()

        # Compute ancestors for the replacement tx
        ancestors = self._get_ancestors(new_tx)
        ancestor_size = sum(
            self.transactions[a].size for a in ancestors if a in self.transactions
        )
        entry = MempoolEntry(
            tx=new_tx, fee=new_fee, fee_rate=new_fee_rate,
            size=new_size, time_added=time.time(), height_added=height,
            ancestor_count=len(ancestors) + 1,
            ancestor_size=ancestor_size + new_size,
        )
        self.transactions[new_txid] = entry
        self.current_size += new_size
        for inp in new_tx.inputs:
            self.spent_outputs.add((inp.prev_txid, inp.prev_vout))
        self._insert_sorted_by_fee_rate(new_txid, new_fee_rate)

        # Update ancestor descendant counts for the new tx's ancestors
        for a_txid in ancestors:
            if a_txid in self.transactions:
                self.transactions[a_txid].descendant_count += 1
                self.transactions[a_txid].descendant_size += new_size

        # Single-pass recount for all remaining txs affected by evictions
        for evicted_id in evicted_ids:
            self._update_descendants_after_removal(evicted_id)

        logger.info(
            f"RBF: replaced {len(to_evict)} tx(s) with "
            f"{new_txid.hex()[:16]}... (fee {new_fee}, "
            f"rate {new_fee_rate:.2f} sat/vB)"
        )
        return True, ""

    def _insert_sorted_by_fee_rate(self, txid: bytes, fee_rate: float):
        # Binary search and insert (maintains sorted order: lowest to highest)
        left, right = 0, len(self.by_fee_rate)
        
        while left < right:
            mid = (left + right) // 2
            mid_entry = self.transactions[self.by_fee_rate[mid]]
            if mid_entry.fee_rate < fee_rate:
                left = mid + 1
            else:
                right = mid
        
        self.by_fee_rate.insert(left, txid)
    
    def _evict_low_fee_txs(self, needed_space: int):
        freed = 0
        evicted_count = 0
        
        # Evict from lowest fee rate (start of list)
        while self.by_fee_rate and freed < needed_space:
            txid = self.by_fee_rate[0]  # Lowest fee rate
            entry = self.transactions[txid]
            size = entry.size
            self.remove_transaction(txid)
            freed += size
            evicted_count += 1
        
        if evicted_count > 0:
            logger.info(
                f"Evicted {evicted_count} transactions to free {freed} bytes "
                f"(needed: {needed_space})"
            )
    
    def clear(self) -> None:
        """Clear all transactions from the mempool."""
        with self._lock:
            count = len(self.transactions)
            self.transactions.clear()
            self.spent_outputs.clear()
            self.by_fee_rate.clear()
            self.current_size = 0
            logger.info(f"Cleared mempool ({count} transactions removed)")

    # Persistence

    MEMPOOL_DUMP_VERSION = 1

    def dump_to_file(self, filepath: str) -> int:
        """
        Persist mempool to disk.

        File format:
        - version byte (1)
        - tx count (4 bytes LE)
        - for each tx:
            - raw_tx_len (4 bytes LE)
            - raw_tx_bytes (witness-format serialization)
            - fee (8 bytes LE)
            - time_added (double, 8 bytes LE)

        Returns the number of transactions written.
        """
        from ouroboros.p2p_messages import encode_varint

        count = len(self.transactions)
        if count == 0:
            # Remove stale file
            try:
                os.remove(filepath)
            except FileNotFoundError:
                pass
            return 0

        tmp = filepath + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(struct.pack("<B", self.MEMPOOL_DUMP_VERSION))
                f.write(struct.pack("<I", count))
                for entry in self.transactions.values():
                    raw = entry.tx.serialize_with_witness()
                    f.write(struct.pack("<I", len(raw)))
                    f.write(raw)
                    f.write(struct.pack("<q", entry.fee))
                    f.write(struct.pack("<d", entry.time_added))
            os.replace(tmp, filepath)
            logger.info(f"Saved {count} mempool transactions to {filepath}")
            return count
        except Exception as e:
            logger.warning(f"Failed to dump mempool: {e}")
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
            return 0

    def load_from_file(self, filepath: str, height: int) -> int:
        """
        Reload mempool from a previous dump.

        Each transaction is re-validated before being accepted (UTXOs may
        have changed since the dump was written).  Transactions that fail
        validation are silently skipped.

        Returns the number of transactions successfully loaded.
        """
        from ouroboros.p2p_messages import TxMessage

        if not os.path.exists(filepath):
            return 0

        loaded = 0
        skipped = 0
        try:
            with open(filepath, "rb") as f:
                ver_bytes = f.read(1)
                if not ver_bytes:
                    return 0
                version = struct.unpack("<B", ver_bytes)[0]
                if version != self.MEMPOOL_DUMP_VERSION:
                    logger.warning(
                        f"Unknown mempool.dat version {version}, skipping"
                    )
                    return 0

                count_bytes = f.read(4)
                if len(count_bytes) < 4:
                    return 0
                count = struct.unpack("<I", count_bytes)[0]

                for _ in range(count):
                    # Read tx length + raw bytes
                    raw_len_bytes = f.read(4)
                    if len(raw_len_bytes) < 4:
                        break
                    raw_len = struct.unpack("<I", raw_len_bytes)[0]
                    raw = f.read(raw_len)
                    if len(raw) < raw_len:
                        break

                    # Read fee and time_added
                    meta = f.read(16)  # 8 + 8
                    if len(meta) < 16:
                        break
                    fee = struct.unpack("<q", meta[:8])[0]
                    time_added = struct.unpack("<d", meta[8:16])[0]

                    # Deserialize the transaction
                    try:
                        tx_msg = TxMessage.from_payload(raw)
                        tx = tx_msg.transaction
                    except Exception:
                        skipped += 1
                        continue

                    # Re-validate and add
                    ok, err = self.add_transaction(tx, height)
                    if ok:
                        # Restore original time_added
                        txid = tx.get_txid()
                        if txid in self.transactions:
                            self.transactions[txid].time_added = time_added
                        loaded += 1
                    else:
                        skipped += 1

            logger.info(
                f"Loaded {loaded} mempool transactions from {filepath}"
                + (f" ({skipped} skipped)" if skipped else "")
            )
        except Exception as e:
            logger.warning(f"Failed to load mempool from {filepath}: {e}")

        # Remove the file after loading (one-shot)
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass

        return loaded

    def has_transaction(self, txid: bytes) -> bool:
        """
        Check if transaction is in mempool.
        
        Args:
            txid: Transaction ID to check
            
        Returns:
            True if transaction is in mempool
        """
        return txid in self.transactions
    
    def get_transaction_entry(self, txid: bytes) -> Optional[MempoolEntry]:
        """
        Get mempool entry for a transaction.
        
        Args:
            txid: Transaction ID
            
        Returns:
            MempoolEntry or None if not found
        """
        return self.transactions.get(txid)

    # --- Package Validation / CPFP ---

    def validate_package(
        self, txs: List[Transaction], height: int
    ) -> Tuple[bool, str]:
        """
        Validate and accept a package of transactions (CPFP support).

        Transactions must be topologically sorted (parents before children).
        The package is evaluated as a unit: individual transactions are allowed
        to fall below the minimum relay fee as long as the *package* fee rate
        meets the mempool minimum.

        Args:
            txs: List of transactions in topological order
            height: Current block height

        Returns:
            (success, error_message)
        """
        with self._lock:
            return self._validate_package_inner(txs, height)

    def _validate_package_inner(
        self, txs: List[Transaction], height: int
    ) -> Tuple[bool, str]:
        """Unlocked implementation of validate_package."""
        if not txs:
            return False, "Empty package"

        if len(txs) > MAX_PACKAGE_COUNT:
            return False, (
                f"Package too large: {len(txs)} > {MAX_PACKAGE_COUNT}"
            )

        # Check for duplicates within the package
        seen_txids: Set[bytes] = set()
        for tx in txs:
            txid = tx.get_txid()
            if txid in seen_txids:
                return False, f"Duplicate transaction in package: {txid.hex()[:16]}..."
            seen_txids.add(txid)

        # Check total weight
        total_weight = sum([tx.get_weight() for tx in txs])
        if total_weight > MAX_PACKAGE_WEIGHT:
            return False, (
                f"Package weight {total_weight} exceeds {MAX_PACKAGE_WEIGHT}"
            )

        # Check for double-spends within the package
        package_spent: Set[OutPoint] = set()
        for tx in txs:
            for inp in tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                if op in package_spent:
                    return False, (
                        f"Double-spend within package: "
                        f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout}"
                    )
                package_spent.add(op)

        # Verify topological order: every input that references a package
        # tx must reference one that appeared earlier.
        txid_to_pos = {tx.get_txid(): i for i, tx in enumerate(txs)}
        for i, tx in enumerate(txs):
            for inp in tx.inputs:
                parent_pos = txid_to_pos.get(inp.prev_txid)
                if parent_pos is not None and parent_pos >= i:
                    return False, (
                        "Package not in topological order: "
                        f"tx at position {i} spends output of tx at position {parent_pos}"
                    )

        # Ephemeral dust check for v3 transactions
        # Any v3 tx in the package that has dust outputs must have every
        # such output spent by another transaction within the same package.
        # Reference: Bitcoin Core policy/ephemeral_policy.cpp
        for tx in txs:
            if tx.version != 3:
                continue
            dust_indices = _has_ephemeral_dust(tx)
            if not dust_indices:
                continue
            txid = tx.get_txid()
            for dust_vout in dust_indices:
                dust_outpoint: OutPoint = (txid, dust_vout)
                if dust_outpoint not in package_spent:
                    return False, (
                        f"v3 tx {txid.hex()[:16]}... has unspent ephemeral "
                        f"dust output at index {dust_vout}"
                    )

        # Validate each transaction (consensus checks only)
        for tx in txs:
            txid = tx.get_txid()
            if txid in self.transactions:
                return False, f"Transaction {txid.hex()[:16]}... already in mempool"

        # Check conflicts with existing mempool (any double-spend)
        for tx in txs:
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_vout)
                if op in self.spent_outputs:
                    return False, (
                        f"Package conflicts with mempool: "
                        f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout} already spent"
                    )

        # Compute package fee rate.
        # Build a temporary UTXO view that includes outputs created by
        # earlier transactions in the package so child fees can be computed.
        package_outputs: Dict[OutPoint, int] = {}  # (txid, vout) → value
        total_fees = 0
        total_size = 0

        for tx in txs:
            txid = tx.get_txid()
            tx_size = len(tx.serialize())

            # Sum inputs — from chain UTXO set, mempool, or package
            total_input = 0
            for inp in tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                if op in package_outputs:
                    total_input += package_outputs[op]
                else:
                    # Check mempool parent output
                    parent_entry = self.transactions.get(inp.prev_txid)
                    if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                        total_input += parent_entry.tx.outputs[inp.prev_vout].value
                    else:
                        utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
                        if utxo:
                            total_input += utxo['value']
                        else:
                            return False, (
                                f"UTXO not found for package tx: "
                                f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout}"
                            )

            total_output = sum(out.value for out in tx.outputs)
            fee = total_input - total_output
            if fee < 0:
                return False, f"Negative fee in package tx {txid.hex()[:16]}..."

            total_fees += fee
            total_size += tx_size

            # Register this tx's outputs for children in the package
            for vout, out in enumerate(tx.outputs):
                package_outputs[(txid, vout)] = out.value

        # Package fee rate check (CPFP: package rate must meet minimum)
        package_fee_rate = total_fees / total_size if total_size > 0 else 0
        min_relay = (total_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        if total_fees < min_relay:
            return False, (
                f"Package fee rate too low: {package_fee_rate:.2f} sat/vB "
                f"(need {DEFAULT_MIN_RELAY_TX_FEE / 1000:.2f} sat/vB)"
            )

        # Consensus-validate each transaction
        # Build a set of txids available in the package so the validator
        # doesn't reject child txs for missing parents.
        for tx in txs:
            valid, error = self.validator.validate_transaction(tx, height)
            if not valid:
                return False, f"Package tx {tx.get_txid().hex()[:16]}... invalid: {error}"

        # All checks passed — add transactions in topological order.
        # Re-compute per-tx fee info and skip the per-tx minimum fee check
        # (package rate already validated above).
        added_txids: List[bytes] = []
        for tx in txs:
            txid = tx.get_txid()
            tx_size = len(tx.serialize())

            # Compute fee for this individual transaction
            tx_input = 0
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_vout)
                parent_entry = self.transactions.get(inp.prev_txid)
                if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                    tx_input += parent_entry.tx.outputs[inp.prev_vout].value
                else:
                    utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
                    if utxo:
                        tx_input += utxo['value']
            tx_output = sum(out.value for out in tx.outputs)
            fee = tx_input - tx_output
            fee_rate = fee / tx_size if tx_size > 0 else 0

            ancestors = self._get_ancestors(tx)
            ancestor_size = sum(
                self.transactions[a].size
                for a in ancestors if a in self.transactions
            )

            entry = MempoolEntry(
                tx=tx,
                fee=fee,
                fee_rate=fee_rate,
                size=tx_size,
                time_added=time.time(),
                height_added=height,
                ancestor_count=len(ancestors) + 1,
                ancestor_size=ancestor_size + tx_size,
            )
            self.transactions[txid] = entry
            self.current_size += tx_size

            for inp in tx.inputs:
                self.spent_outputs.add((inp.prev_txid, inp.prev_vout))

            self._insert_sorted_by_fee_rate(txid, fee_rate)

            # Update ancestor descendant counts
            for a_txid in ancestors:
                if a_txid in self.transactions:
                    self.transactions[a_txid].descendant_count += 1
                    self.transactions[a_txid].descendant_size += tx_size

            added_txids.append(txid)

        logger.info(
            f"Accepted package of {len(added_txids)} txs "
            f"(total fee {total_fees}, package rate {package_fee_rate:.2f} sat/vB)"
        )

        # Resolve any orphans that may be waiting on these transactions
        for txid in added_txids:
            self._resolve_orphans(txid, height)

        return True, ""