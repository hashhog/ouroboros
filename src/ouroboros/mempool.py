"""
Transaction mempool management.

This module implements the unconfirmed transaction pool with fee rate
sorting, double spend detection, size management, ancestor/descendant
limits, and standardness checks.
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
import time
import logging

from ouroboros.database import Transaction
from ouroboros.validation import TransactionValidator

logger = logging.getLogger(__name__)

# OutPoint is a tuple of (txid: bytes, vout: int)
OutPoint = Tuple[bytes, int]

# Policy constants matching Bitcoin Core
MAX_STANDARD_TX_WEIGHT = 400_000
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
MAX_ANCESTOR_COUNT = 25
MAX_DESCENDANT_COUNT = 25
MAX_ANCESTOR_SIZE_KVB = 101
MAX_DESCENDANT_SIZE_KVB = 101
DUST_RELAY_TX_FEE = 3000  # sat/kB
DEFAULT_MIN_RELAY_TX_FEE = 1000  # sat/kvB
MEMPOOL_EXPIRY_HOURS = 336  # 14 days
TX_MAX_STANDARD_VERSION = 2


def _get_dust_threshold(script_pubkey: bytes) -> int:
    """Calculate the dust threshold for a given output script."""
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


def _is_standard_tx(tx: Transaction) -> Tuple[bool, str]:
    """Check if a transaction is standard (policy, not consensus)."""
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

    # Check for dust outputs
    dust_count = 0
    for out in tx.outputs:
        if out.script_pubkey and out.script_pubkey[0] == 0x6a:
            continue  # OP_RETURN is okay
        threshold = _get_dust_threshold(out.script_pubkey)
        if out.value < threshold:
            dust_count += 1
    if dust_count > 0:
        return False, f"Transaction has {dust_count} dust output(s)"

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


class Mempool:
    """Unconfirmed transaction pool"""
    
    def __init__(
        self,
        validator: TransactionValidator,
        max_size: int = 300_000_000,  # 300 MB
        require_standard: bool = True,
    ):
        """
        Initialize mempool.
        
        Args:
            validator: Transaction validator
            max_size: Maximum mempool size in bytes (default: 300 MB)
            require_standard: Enforce standardness policy (disable for regtest/tests)
        """
        self.validator = validator
        self.max_size = max_size
        self.require_standard = require_standard
        
        self.transactions: Dict[bytes, MempoolEntry] = {}  # txid -> entry
        self.spent_outputs: Set[OutPoint] = set()
        
        # Sorted by fee rate (for mining)
        self.by_fee_rate: List[bytes] = []  # txids sorted by fee rate (lowest first)
        
        # Tracking
        self.current_size = 0  # bytes
    
    def add_transaction(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        """
        Add transaction to mempool.
        
        Args:
            tx: Transaction to add
            height: Current block height
            
        Returns:
            (success, error_message)
        """
        txid = tx.get_txid()
        
        # Check if already in mempool
        if txid in self.transactions:
            return False, "Already in mempool"

        # Standardness checks (policy, not consensus)
        if self.require_standard:
            is_std, reason = _is_standard_tx(tx)
            if not is_std:
                return False, f"Non-standard transaction: {reason}"
        
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

        # Ancestor/descendant limits
        ancestors = self._get_ancestors(tx)
        if len(ancestors) + 1 > MAX_ANCESTOR_COUNT:
            return False, (
                f"Too many ancestors: {len(ancestors) + 1} > {MAX_ANCESTOR_COUNT}")
        ancestor_size = sum(self.transactions[a].size for a in ancestors if a in self.transactions)
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

        # Minimum relay fee
        min_relay = (tx_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        if fee < min_relay:
            return False, f"Below minimum relay fee: {fee} < {min_relay}"
        
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
        return True, ""

    def _get_ancestors(self, tx: Transaction) -> Set[bytes]:
        """Return txids of all mempool ancestors of *tx*."""
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

    def expire_old_transactions(self, current_time: Optional[float] = None) -> int:
        """Remove transactions that have been in the mempool too long."""
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
        return len(expired)
    
    def remove_transaction(self, txid: bytes):
        """
        Remove transaction from mempool.
        
        Args:
            txid: Transaction ID to remove
        """
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
    
    def remove_block_transactions(self, block):
        """
        Remove transactions from mempool that are in a block.
        
        Args:
            block: Block containing transactions to remove
        """
        removed_count = 0
        for tx in block.transactions:
            if not tx.is_coinbase:
                txid = tx.get_txid()
                if txid in self.transactions:
                    self.remove_transaction(txid)
                    removed_count += 1
        
        if removed_count > 0:
            logger.info(f"Removed {removed_count} transactions from mempool (included in block)")
    
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
        return [entry.tx for entry in self.transactions.values()]
    
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
        }
    
    # ── BIP 125 Replace-By-Fee ────────────────────────────────────────

    INCREMENTAL_RELAY_FEE = 1000  # satoshis (matches Bitcoin Core's default)
    MAX_REPLACEMENT_EVICTIONS = 100

    def _find_conflicts(self, tx: Transaction) -> Set[bytes]:
        """Return txids of mempool entries whose inputs overlap with *tx*."""
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
        """Return *txid* plus every descendant in the mempool."""
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
        conflicts = self._find_conflicts(new_tx)
        if not conflicts:
            return False, "No conflicts to replace"

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

        # All checks passed — evict and add
        for txid in to_evict:
            self.remove_transaction(txid)

        new_fee_rate = new_fee / new_size if new_size > 0 else 0
        new_txid = new_tx.get_txid()
        entry = MempoolEntry(
            tx=new_tx, fee=new_fee, fee_rate=new_fee_rate,
            size=new_size, time_added=time.time(), height_added=height,
        )
        self.transactions[new_txid] = entry
        self.current_size += new_size
        for inp in new_tx.inputs:
            self.spent_outputs.add((inp.prev_txid, inp.prev_vout))
        self._insert_sorted_by_fee_rate(new_txid, new_fee_rate)

        logger.info(
            f"RBF: replaced {len(to_evict)} tx(s) with "
            f"{new_txid.hex()[:16]}... (fee {new_fee}, "
            f"rate {new_fee_rate:.2f} sat/vB)"
        )
        return True, ""

    def _insert_sorted_by_fee_rate(self, txid: bytes, fee_rate: float):
        """
        Insert txid into sorted list by fee rate.
        
        Args:
            txid: Transaction ID to insert
            fee_rate: Fee rate of the transaction
        """
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
        """
        Evict lowest fee rate transactions to free space.
        
        Args:
            needed_space: Bytes needed to be freed
        """
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
        count = len(self.transactions)
        self.transactions.clear()
        self.spent_outputs.clear()
        self.by_fee_rate.clear()
        self.current_size = 0
        logger.info(f"Cleared mempool ({count} transactions removed)")
    
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