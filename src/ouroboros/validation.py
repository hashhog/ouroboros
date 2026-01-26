"""Block and transaction validation logic."""

from typing import Tuple, List
import hashlib
from ouroboros.database import BlockchainDatabase, Transaction, TxIn, TxOut, Block
from ouroboros.script import ScriptInterpreter


class BlockValidator:
    """Validates new blocks"""
    
    def __init__(self, db: BlockchainDatabase):
        """
        Initialize block validator.
        
        Args:
            db: Blockchain database for block and UTXO lookups
        """
        self.db = db
        self.tx_validator = TransactionValidator(db)
    
    def validate_block(self, block: Block) -> Tuple[bool, str]:
        """
        Validate a new block completely.
        
        Args:
            block: Block to validate
            
        Returns:
            (is_valid, error_message)
        """
        # 1. Get previous block
        prev_block = self.db.get_block(block.prev_blockhash)
        if not prev_block:
            return False, "Previous block not found"
        
        # Calculate expected height
        expected_height = (prev_block.height or 0) + 1
        
        # 2. Validate header
        if not self._validate_header(block, prev_block):
            return False, "Invalid header"
        
        # 3. Verify merkle root
        if not self._verify_merkle_root(block):
            return False, "Invalid merkle root"
        
        # 4. Validate all transactions
        total_fees = 0
        for i, tx in enumerate(block.transactions):
            if i == 0:  # Coinbase
                if not self._validate_coinbase(tx, expected_height):
                    return False, "Invalid coinbase"
            else:
                valid, error = self.tx_validator.validate_transaction(
                    tx, expected_height
                )
                if not valid:
                    return False, f"Transaction {i} invalid: {error}"
                
                # Calculate fee
                fee = self._calculate_tx_fee(tx)
                total_fees += fee
        
        # 5. Verify coinbase amount
        if not self._verify_coinbase_amount(
            block.transactions[0],
            expected_height,
            total_fees
        ):
            return False, "Coinbase amount invalid"
        
        return True, ""
    
    def apply_block(self, block: Block) -> None:
        """
        Apply block to database (update UTXO set).
        
        Args:
            block: Block to apply
        """
        spent = []
        created = []
        
        # Collect spent and created UTXOs
        for tx in block.transactions:
            # Spent outputs (except coinbase)
            if not tx.is_coinbase:
                for tx_in in tx.inputs:
                    spent.append((tx_in.prev_txid, tx_in.prev_vout))
            
            # Created outputs
            for i, tx_out in enumerate(tx.outputs):
                created.append({
                    'txid': tx.get_txid(),
                    'vout': i,
                    'value': tx_out.value,
                    'script_pubkey': tx_out.script_pubkey,
                })
        
        # Atomic update
        self.db.update_utxo_set(spent, created)
        # Note: Blocks are stored via the Rust API during sync (FastSync/BlockSync).
        # The Python store_block() method is not implemented because it requires
        # reconstructing the Rust BlockWrapper, which is complex. Blocks are
        # automatically stored when syncing via the Rust layer.
    
    def _validate_header(self, block: Block, prev_block: Block) -> bool:
        """
        Validate block header.
        
        Args:
            block: Block to validate
            prev_block: Previous block
            
        Returns:
            True if header is valid
        """
        # Check timestamp is after previous block
        if block.timestamp <= prev_block.timestamp:
            return False
        
        # Check timestamp is not too far in the future (2 hours)
        # This would require current time, so we'll skip for now
        # In production, you'd check: block.timestamp <= current_time + 2*3600
        
        # Check version is valid
        if block.version < 1:
            return False
        
        # Check bits is valid (difficulty target)
        if block.bits == 0:
            return False
        
        return True
    
    def _verify_merkle_root(self, block: Block) -> bool:
        """
        Verify block's merkle root.
        
        Args:
            block: Block to verify
            
        Returns:
            True if merkle root is valid
        """
        txids = [tx.get_txid() for tx in block.transactions]
        calculated_root = self._calculate_merkle_root(txids)
        return calculated_root == block.merkle_root
    
    def _calculate_merkle_root(self, txids: List[bytes]) -> bytes:
        """
        Calculate merkle root from transaction IDs.
        
        Bitcoin's merkle tree algorithm:
        1. Start with transaction IDs
        2. If odd number of items, duplicate the last one
        3. Pair items and hash them together (double SHA256)
        4. Repeat until one hash remains
        
        Args:
            txids: List of transaction IDs (32-byte arrays)
            
        Returns:
            Merkle root (32 bytes)
        """
        if not txids:
            return bytes(32)
        
        if len(txids) == 1:
            return txids[0]
        
        level = list(txids)
        
        while len(level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    # Hash the pair
                    combined = level[i] + level[i + 1]
                else:
                    # Odd number: duplicate the last element
                    combined = level[i] + level[i]
                
                # Double SHA256
                hash1 = hashlib.sha256(combined).digest()
                hash2 = hashlib.sha256(hash1).digest()
                next_level.append(hash2)
            
            level = next_level
        
        return level[0]
    
    def _validate_coinbase(self, tx: Transaction, height: int) -> bool:
        """
        Validate coinbase transaction.
        
        Args:
            tx: Coinbase transaction
            height: Block height
            
        Returns:
            True if coinbase is valid
        """
        # Check it's actually a coinbase
        if not tx.is_coinbase:
            return False
        
        # Check coinbase input
        if len(tx.inputs) != 1:
            return False
        
        coinbase_input = tx.inputs[0]
        if coinbase_input.prev_txid != bytes(32):
            return False
        
        # Check coinbase has at least one output
        if len(tx.outputs) == 0:
            return False
        
        # Check coinbase script_sig is not too large (100 bytes max)
        if len(coinbase_input.script_sig) > 100:
            return False
        
        return True
    
    def _verify_coinbase_amount(
        self,
        coinbase_tx: Transaction,
        height: int,
        total_fees: int
    ) -> bool:
        """
        Verify coinbase amount is correct.
        
        Args:
            coinbase_tx: Coinbase transaction
            height: Block height
            total_fees: Total fees from all transactions in block
            
        Returns:
            True if coinbase amount is valid
        """
        block_subsidy = self._calculate_block_subsidy(height)
        expected_amount = block_subsidy + total_fees
        
        total_output = sum(out.value for out in coinbase_tx.outputs)
        
        # Coinbase amount should equal subsidy + fees
        return total_output == expected_amount
    
    def _calculate_block_subsidy(self, height: int) -> int:
        """
        Calculate block subsidy (50 BTC halving every 210000 blocks).
        
        Args:
            height: Block height
            
        Returns:
            Block subsidy in satoshis
        """
        halvings = height // 210000
        if halvings >= 64:
            return 0
        return 50 * 100_000_000 >> halvings
    
    def _calculate_tx_fee(self, tx: Transaction) -> int:
        """
        Calculate transaction fee.
        
        Args:
            tx: Transaction to calculate fee for
            
        Returns:
            Fee in satoshis
        """
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo:
                total_input += utxo['value']
        
        total_output = sum(out.value for out in tx.outputs)
        return total_input - total_output


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
