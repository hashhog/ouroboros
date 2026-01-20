"""Block and transaction validation logic."""

from typing import Tuple
from ouroboros.database import BlockchainDatabase, Transaction, TxIn, TxOut
from ouroboros.script import ScriptInterpreter


class BlockValidator:
    """Validates Bitcoin blocks."""

    def __init__(self) -> None:
        """Initialize the block validator."""
        pass

    async def validate_block(self, block: bytes) -> bool:
        """Validate a Bitcoin block.

        Args:
            block: Raw block data

        Returns:
            True if block is valid, False otherwise
        """
        # TODO: Implement block validation
        return True

    async def validate_block_header(self, header: bytes) -> bool:
        """Validate a block header.

        Args:
            header: Raw block header data

        Returns:
            True if header is valid, False otherwise
        """
        # TODO: Implement header validation
        return True


class TransactionValidator:
    """Validates transactions for mempool and new blocks"""
    
    def __init__(self, db: BlockchainDatabase):
        """
        Initialize transaction validator.
        
        Args:
            db: Blockchain database for UTXO lookups
        """
        self.db = db
        self.script_interpreter = ScriptInterpreter()
        
    def validate_transaction(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        """
        Validate transaction.
        
        Args:
            tx: Transaction to validate
            height: Block height (for coinbase validation)
            
        Returns:
            (is_valid, error_message)
        """
        # 1. Check structure
        if not self._check_structure(tx):
            return False, "Invalid structure"
        
        # 2. Check inputs exist
        total_input = 0
        for i, tx_in in enumerate(tx.inputs):
            utxo = self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if not utxo:
                return False, f"Input not found: {tx_in.prev_txid.hex()}:{tx_in.prev_vout}"
            
            # 3. Verify signatures
            if not self._verify_input_signature(tx, tx_in, utxo, i):
                return False, f"Invalid signature for input {i}"
            
            total_input += utxo['value']
        
        # 4. Check amounts
        total_output = sum(out.value for out in tx.outputs)
        if total_input < total_output:
            return False, f"Outputs exceed inputs: {total_output} > {total_input}"
        
        # 5. Check fee
        fee = total_input - total_output
        min_fee = self._calculate_min_fee(tx)
        if fee < min_fee:
            return False, f"Fee too low: {fee} < {min_fee} (minimum {min_fee} satoshis)"
        
        return True, ""
    
    def _check_structure(self, tx: Transaction) -> bool:
        """Check basic transaction structure"""
        # Check version is valid
        if tx.version < 1 or tx.version > 2:
            return False
        
        # Check we have at least one input (unless coinbase)
        if len(tx.inputs) == 0:
            return False
        
        # Check we have at least one output
        if len(tx.outputs) == 0:
            return False
        
        # Check locktime is valid
        if tx.locktime < 0 or tx.locktime > 0xffffffff:
            return False
        
        # Check all outputs have valid values
        for out in tx.outputs:
            if out.value < 0:
                return False
            if out.value > 21000000 * 100000000:  # Max Bitcoin supply
                return False
        
        return True
    
    def _verify_input_signature(
        self,
        tx: Transaction,
        tx_in: TxIn,
        utxo: dict,
        input_index: int
    ) -> bool:
        """
        Verify signature for one input.
        
        Args:
            tx: The transaction
            tx_in: The input to verify
            utxo: UTXO dictionary with 'script_pubkey' key
            input_index: Index of the input in the transaction
            
        Returns:
            True if signature is valid
        """
        return self.script_interpreter.verify(
            tx_in.script_sig,
            bytes(utxo['script_pubkey']),
            tx,
            input_index
        )
    
    def _calculate_min_fee(self, tx: Transaction) -> int:
        """
        Calculate minimum relay fee (1 sat/vbyte).
        
        Args:
            tx: Transaction to calculate fee for
            
        Returns:
            Minimum fee in satoshis
        """
        # Get transaction size in bytes
        tx_size = len(tx.serialize())
        
        # Minimum fee: 1 satoshi per vbyte
        # For simplicity, we use bytes (vbytes would require segwit calculation)
        min_fee = tx_size  # 1 sat/vbyte
        
        # Minimum fee floor (dust threshold)
        if min_fee < 1000:  # 1000 satoshis minimum
            min_fee = 1000
        
        return min_fee


class ValidationError(Exception):
    """Raised when validation fails."""

    pass
