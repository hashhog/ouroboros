"""
Transaction mempool management.

This module implements the unconfirmed transaction pool with fee rate
sorting, double spend detection, and size management.
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
import time
import logging

from ouroboros.database import Transaction
from ouroboros.validation import TransactionValidator

logger = logging.getLogger(__name__)

# OutPoint is a tuple of (txid: bytes, vout: int)
OutPoint = Tuple[bytes, int]


@dataclass
class MempoolEntry:
    """Entry in the mempool"""
    tx: Transaction
    fee: int
    fee_rate: float  # sat/vbyte
    size: int
    time_added: float
    height_added: int


class Mempool:
    """Unconfirmed transaction pool"""
    
    def __init__(
        self,
        validator: TransactionValidator,
        max_size: int = 300_000_000  # 300 MB
    ):
        """
        Initialize mempool.
        
        Args:
            validator: Transaction validator
            max_size: Maximum mempool size in bytes (default: 300 MB)
        """
        self.validator = validator
        self.max_size = max_size
        
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
        
        # Validate transaction
        valid, error = self.validator.validate_transaction(tx, height)
        if not valid:
            return False, error
        
        # Check for conflicts (double spends)
        for tx_in in tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            if outpoint in self.spent_outputs:
                return False, "Double spend detected"
        
        # Check mempool size
        tx_size = len(tx.serialize())
        if self.current_size + tx_size > self.max_size:
            # Evict lowest fee rate transactions
            self._evict_low_fee_txs(tx_size)
        
        # Calculate fee
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo:
                total_input += utxo['value']
            else:
                # UTXO not found - this shouldn't happen after validation
                return False, f"UTXO not found: {tx_in.prev_txid.hex()[:16]}...:{tx_in.prev_vout}"
        
        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output
        
        if fee < 0:
            return False, "Negative fee"
        
        fee_rate = fee / tx_size if tx_size > 0 else 0
        
        # Add to mempool
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee_rate,
            size=tx_size,
            time_added=time.time(),
            height_added=height
        )
        
        self.transactions[txid] = entry
        self.current_size += tx_size
        
        # Track spent outputs
        for tx_in in tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            self.spent_outputs.add(outpoint)
        
        # Insert sorted by fee rate
        self._insert_sorted_by_fee_rate(txid, fee_rate)
        
        logger.info(
            f"Added transaction {txid.hex()[:16]}... to mempool "
            f"(fee: {fee}, rate: {fee_rate:.2f} sat/vbyte)"
        )
        return True, ""
    
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