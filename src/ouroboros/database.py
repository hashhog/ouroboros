"""
Python wrapper for blockchain database operations.

This module provides a high-level Python interface to the Rust blockchain database
implementation, allowing Python code to interact with the blockchain storage layer.
"""

from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
import sync  # Rust extension module
import hashlib


@dataclass
class Block:
    """Bitcoin block representation"""
    version: int
    prev_blockhash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    transactions: List['Transaction']
    hash: bytes
    height: Optional[int] = None  # Block height (if known)
    
    def hash(self) -> bytes:
        """Compute block hash"""
        return self.hash
    
    def serialize(self) -> bytes:
        """
        Serialize block to Bitcoin wire format.
        
        Format:
        - version (4 bytes, little-endian)
        - prev_blockhash (32 bytes, reversed for wire format)
        - merkle_root (32 bytes, reversed for wire format)
        - timestamp (4 bytes, little-endian)
        - bits (4 bytes, little-endian)
        - nonce (4 bytes, little-endian)
        - tx_count (varint)
        - transactions (variable, each transaction serialized)
        
        Returns:
            Serialized block bytes
            
        Note:
            Block hash is in display format (big-endian), but wire format uses little-endian
            So we need to reverse hashes when serializing
        """
        from ouroboros.p2p_messages import encode_varint
        
        data = bytearray()
        
        # Serialize header (80 bytes)
        # Version (4 bytes)
        data.extend(self.version.to_bytes(4, 'little', signed=True))
        
        # Previous block hash (32 bytes, reverse from display format to wire format)
        data.extend(self.prev_blockhash[::-1])
        
        # Merkle root (32 bytes, reverse from display format to wire format)
        data.extend(self.merkle_root[::-1])
        
        # Timestamp (4 bytes)
        data.extend(self.timestamp.to_bytes(4, 'little'))
        
        # Bits (4 bytes)
        data.extend(self.bits.to_bytes(4, 'little'))
        
        # Nonce (4 bytes)
        data.extend(self.nonce.to_bytes(4, 'little'))
        
        # Transaction count (varint)
        data.extend(encode_varint(len(self.transactions)))
        
        # Serialize each transaction
        for tx in self.transactions:
            tx_bytes = tx.serialize()
            data.extend(tx_bytes)
        
        return bytes(data)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Block':
        """
        Deserialize block from Bitcoin wire format.
        
        Format:
        - version (4 bytes)
        - prev_blockhash (32 bytes)
        - merkle_root (32 bytes)
        - timestamp (4 bytes)
        - bits (4 bytes)
        - nonce (4 bytes)
        - tx_count (varint)
        - transactions (variable)
        
        Args:
            data: Block data in Bitcoin wire format
            
        Returns:
            Block object
            
        Raises:
            ValueError: If data is invalid or too short
        """
        from ouroboros.p2p_messages import decode_varint, TxMessage
        
        offset = 0
        
        if len(data) < 80:  # Minimum header size
            raise ValueError("Block data too short for header")
        
        # Parse header (80 bytes)
        version = int.from_bytes(data[offset:offset+4], byteorder='little', signed=True)
        offset += 4
        
        prev_blockhash = data[offset:offset+32][::-1]  # Reverse for display format (big-endian)
        offset += 32
        
        merkle_root = data[offset:offset+32][::-1]  # Reverse for display format
        offset += 32
        
        timestamp = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4
        
        bits = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4
        
        nonce = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4
        
        # Parse transaction count (varint)
        if len(data) <= offset:
            raise ValueError("Block data too short for transaction count")
        tx_count, varint_size = decode_varint(data, offset)
        offset += varint_size
        
        # Parse transactions
        # We need to track transaction sizes accurately
        # Since transactions can have variable sizes and we need to know where each ends,
        # we'll parse each transaction and use its serialized size to track bytes consumed
        transactions = []
        for i in range(tx_count):
            if offset >= len(data):
                raise ValueError(f"Block data too short for transaction {i}")
            
            # Store offset before parsing this transaction
            tx_start_offset = offset
            
            # Parse transaction using TxMessage.from_payload
            tx_data = data[offset:]
            try:
                tx_msg = TxMessage.from_payload(tx_data)
                tx = tx_msg.transaction
                
                # Calculate transaction size by serializing it back
                # Transaction.serialize() produces wire-format compatible output,
                # so the size should match the original wire format
                tx_serialized = tx.serialize()
                tx_size = len(tx_serialized)
                
                # Validate that we haven't gone past the end of data
                remaining = len(data) - tx_start_offset
                if tx_size > remaining:
                    # If calculated size goes past end, this indicates either:
                    # 1. Transaction serialization doesn't match wire format exactly
                    # 2. Corrupted block data
                    if remaining < 60:  # Minimum transaction size
                        raise ValueError(
                            f"Transaction {i} size calculation error: "
                            f"calculated {tx_size} bytes but only {remaining} bytes remaining"
                        )
                    # Use remaining bytes as fallback (this is a workaround)
                    # Ideally, transaction serialization should match wire format exactly
                    tx_size = remaining
                
                offset = tx_start_offset + tx_size
                transactions.append(tx)
                
            except ValueError as e:
                # If parsing fails, try to recover by finding next transaction
                # This is a fallback - ideally we should parse correctly
                raise ValueError(f"Error parsing transaction {i} at offset {tx_start_offset}: {e}")
            except Exception as e:
                raise ValueError(f"Unexpected error parsing transaction {i}: {e}")
        
        # Calculate block hash
        import hashlib
        block_header = data[0:80]
        block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()[::-1]  # Reverse for display
        
        return cls(
            version=version,
            prev_blockhash=prev_blockhash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
            transactions=transactions,
            hash=block_hash,
            height=None  # Height not in wire format
        )


@dataclass
class Transaction:
    """Bitcoin transaction representation"""
    txid: bytes
    version: int
    locktime: int
    inputs: List['TxIn']
    outputs: List['TxOut']
    
    @property
    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction"""
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == bytes(32)
    
    def get_txid(self) -> bytes:
        """Get transaction ID"""
        return self.txid
    
    def serialize(self) -> bytes:
        """
        Serialize transaction to bytes for fee calculation.
        
        This is a simplified serialization for size estimation.
        For full Bitcoin protocol serialization, use the Rust layer.
        """
        # Version (4 bytes)
        data = self.version.to_bytes(4, 'little')
        
        # Input count (varint)
        data += self._encode_varint(len(self.inputs))
        
        # Inputs
        for tx_in in self.inputs:
            data += tx_in.prev_txid  # 32 bytes
            data += tx_in.prev_vout.to_bytes(4, 'little')
            data += self._encode_varint(len(tx_in.script_sig))
            data += tx_in.script_sig
            data += tx_in.sequence.to_bytes(4, 'little')
        
        # Output count (varint)
        data += self._encode_varint(len(self.outputs))
        
        # Outputs
        for tx_out in self.outputs:
            data += tx_out.value.to_bytes(8, 'little')
            data += self._encode_varint(len(tx_out.script_pubkey))
            data += tx_out.script_pubkey
        
        # Locktime (4 bytes)
        data += self.locktime.to_bytes(4, 'little')
        
        return data
    
    def _encode_varint(self, value: int) -> bytes:
        """Encode variable-length integer"""
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')
    
    def get_weight(self) -> int:
        """
        Calculate transaction weight for SegWit transactions.
        
        Weight = (non-witness bytes * 4) + witness bytes
        
        For non-SegWit transactions (current implementation):
        - weight = size * 4
        - This is because non-witness bytes = total size, witness bytes = 0
        
        For SegWit transactions (when witness data is stored):
        - Would need to calculate non-witness bytes separately
        - Would need to calculate witness bytes separately
        
        Returns:
            Transaction weight
        """
        # Get non-witness size (current serialize() excludes witness)
        non_witness_bytes = len(self.serialize())
        
        # For now, assume no witness data (non-SegWit transaction)
        # TODO: When witness data is stored in Transaction, calculate witness bytes
        witness_bytes = 0
        
        # Weight = (non-witness bytes * 4) + witness bytes
        return (non_witness_bytes * 4) + witness_bytes
    
    def get_vsize(self) -> int:
        """
        Calculate virtual size (vsize) for SegWit transactions.
        
        vsize = (weight + 3) // 4  (round up)
        
        For non-SegWit transactions, vsize = size (since weight = size * 4)
        
        Returns:
            Virtual size in bytes
        """
        weight = self.get_weight()
        # vsize = ceil(weight / 4) = (weight + 3) // 4
        return (weight + 3) // 4


@dataclass
class TxIn:
    """Bitcoin transaction input"""
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes
    sequence: int


@dataclass
class TxOut:
    """Bitcoin transaction output"""
    value: int
    script_pubkey: bytes


class BlockchainDatabase:
    """Read/write access to blockchain data using Rust backend"""
    
    def __init__(self, data_dir: str):
        """
        Initialize blockchain database.
        
        Args:
            data_dir: Path to database directory
        """
        self._db = sync.PyBlockchainDB(data_dir)
        self._data_dir = data_dir
    
    def get_block(self, block_hash: bytes) -> Optional[Block]:
        """
        Get block by hash.
        
        Args:
            block_hash: 32-byte block hash
            
        Returns:
            Block object or None if not found
        """
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        
        py_block = self._db.get_block(block_hash)
        if py_block is None:
            return None
        
        return self._py_block_to_block(py_block)
    
    def get_block_by_height(self, height: int) -> Optional[Block]:
        """
        Get block by height.
        
        Args:
            height: Block height
            
        Returns:
            Block object or None if not found
        """
        py_block = self._db.get_block_by_height(height)
        if py_block is None:
            return None
        
        return self._py_block_to_block(py_block)
    
    def get_utxo(self, txid: bytes, vout: int) -> Optional[Dict[str, Any]]:
        """
        Get UTXO.
        
        Args:
            txid: Transaction ID (32 bytes)
            vout: Output index
            
        Returns:
            UTXO dictionary with keys: txid, vout, value, script_pubkey
            or None if not found
        """
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        
        py_utxo = self._db.get_utxo(txid, vout)
        if py_utxo is None:
            return None
        
        return {
            'txid': py_utxo.txid,
            'vout': py_utxo.vout,
            'value': py_utxo.value,
            'script_pubkey': bytes(py_utxo.script_pubkey),
        }
    
    def store_block(self, block: Block) -> None:
        """
        Store new block.
        
        Args:
            block: Block object to store
            
        Note:
            This requires reconstructing the Rust BlockWrapper, which is complex.
            For now, use the Rust API directly via FastSync or BlockSync.
        """
        raise NotImplementedError(
            "store_block requires BlockWrapper reconstruction. "
            "Use Rust API directly via FastSync.store_block() or BlockSync"
        )
    
    def restore_utxo(self, txid: bytes, vout: int, value: int, script_pubkey: bytes) -> None:
        """
        Restore a single UTXO to the database.
        
        This is used during chain reorganization to restore UTXOs that were spent.
        
        The Rust database has an `add_utxo` method, but it's not exposed via PyO3.
        For now, we use a workaround by attempting to use update_utxo_set, or log a warning.
        
        Args:
            txid: Transaction ID that created the UTXO
            vout: Output index
            value: Output value in satoshis
            script_pubkey: Script pubkey (locking script)
        """
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Try to use Rust API if available
            # The Rust database has add_utxo() but it's not exposed via PyO3
            # We need to use update_utxo_set as a workaround
            from sync import PyUTXO
            
            py_utxo = PyUTXO()
            py_utxo.txid = txid.hex()
            py_utxo.vout = vout
            py_utxo.value = value
            py_utxo.script_pubkey = list(script_pubkey)
            
            # Try to use update_utxo_set with empty spent list and single created UTXO
            # Note: update_utxo_set may not be fully implemented
            try:
                self._db.update_utxo_set([], [py_utxo])
                logger.debug(f"Restored UTXO {txid.hex()[:16]}...:{vout}")
            except (NotImplementedError, AttributeError, Exception) as e:
                # If update_utxo_set doesn't work, log a warning
                # Full implementation would require exposing add_utxo via PyO3
                logger.warning(
                    f"Cannot restore UTXO {txid.hex()[:16]}...:{vout} - "
                    f"update_utxo_set not fully implemented ({type(e).__name__}). "
                    f"UTXO restoration may be incomplete. "
                    f"Consider exposing add_utxo() from Rust database via PyO3."
                )
        except ImportError:
            # Rust module not available
            logger.warning(
                f"Cannot restore UTXO - Rust sync module not available. "
                f"UTXO restoration skipped."
            )
        except Exception as e:
            logger.error(f"Error restoring UTXO {txid.hex()[:16]}...:{vout}: {e}")
    
    def remove_utxo(self, txid: bytes, vout: int) -> None:
        """
        Remove a UTXO from the database.
        
        This is used during chain reorganization to remove UTXOs that were created
        in disconnected blocks.
        
        The Rust database has spend_utxo() which removes a UTXO, but it's not exposed via PyO3.
        We use update_utxo_set as a workaround.
        
        Args:
            txid: Transaction ID that created the UTXO
            vout: Output index
        """
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Use update_utxo_set with spent list containing this UTXO
            # The Rust database has spend_utxo() but it's not exposed via PyO3
            try:
                self._db.update_utxo_set([(txid, vout)], [])
                logger.debug(f"Removed UTXO {txid.hex()[:16]}...:{vout}")
            except (NotImplementedError, AttributeError, Exception) as e:
                # If update_utxo_set doesn't work, log a warning
                # Full implementation would require exposing spend_utxo via PyO3
                logger.warning(
                    f"Cannot remove UTXO {txid.hex()[:16]}...:{vout} - "
                    f"update_utxo_set not fully implemented ({type(e).__name__}). "
                    f"UTXO removal may be incomplete. "
                    f"Consider exposing spend_utxo() from Rust database via PyO3."
                )
        except Exception as e:
            logger.error(f"Error removing UTXO {txid.hex()[:16]}...:{vout}: {e}")
    
    def update_utxo_set(
        self,
        spent: List[Tuple[bytes, int]],
        created: List[Dict[str, Any]]
    ) -> None:
        """
        Atomic UTXO update.
        
        Args:
            spent: List of (txid, vout) tuples for spent UTXOs
            created: List of UTXO dictionaries with keys: txid, vout, value, script_pubkey
            
        Note:
            This requires reconstructing Rust UTXO objects, which is complex.
            For now, use the Rust API directly.
        """
        raise NotImplementedError(
            "update_utxo_set requires UTXO reconstruction. "
            "Use restore_utxo() and remove_utxo() methods instead, "
            "or use Rust API directly via BlockchainDB.batch_update_utxos()"
        )
    
    def get_best_block(self) -> Tuple[bytes, int]:
        """
        Get chain tip.
        
        Returns:
            Tuple of (block_hash, height)
        """
        hash_bytes, height = self._db.get_best_block()
        return (bytes(hash_bytes), height)
    
    def get_block_hash_by_height(self, height: int) -> Optional[bytes]:
        """
        Get block hash by height.
        
        Args:
            height: Block height
            
        Returns:
            Block hash (32 bytes) or None if not found
        """
        try:
            block_hash = self._db.get_block_hash_by_height(height)
            if block_hash is None:
                return None
            return bytes(block_hash)
        except Exception:
            # Fallback: get block by height and extract hash
            block = self.get_block_by_height(height)
            if block:
                return block.hash if hasattr(block, 'hash') else None
            return None
    
    def store_block_chainwork(self, block_hash: bytes, chainwork: int) -> None:
        """
        Store chainwork for a block.
        
        Args:
            block_hash: 32-byte block hash
            chainwork: Chainwork value (integer)
            
        Note:
            This uses a simple in-memory cache. For persistence,
            consider adding to the Rust database backend.
        """
        if not hasattr(self, '_chainwork_cache'):
            self._chainwork_cache: Dict[bytes, int] = {}
        
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        
        self._chainwork_cache[block_hash] = chainwork
    
    def get_block_chainwork(self, block_hash: bytes) -> int:
        """
        Get chainwork for a block.
        
        Args:
            block_hash: 32-byte block hash
            
        Returns:
            Chainwork value or 0 if not found
        """
        if not hasattr(self, '_chainwork_cache'):
            self._chainwork_cache: Dict[bytes, int] = {}
        
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        
        return self._chainwork_cache.get(block_hash, 0)
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Database operations are already atomic via RocksDB
        return False
    
    def _py_block_to_block(self, py_block) -> Block:
        # Type hint: py_block should be sync.PyBlock if available
        """Convert PyBlock to Block"""
        transactions = []
        for py_tx in py_block.transactions:
            inputs = [
                TxIn(
                    prev_txid=bytes(py_in.prev_txid),
                    prev_vout=py_in.prev_vout,
                    script_sig=bytes(py_in.script_sig),
                    sequence=py_in.sequence,
                )
                for py_in in py_tx.inputs
            ]
            outputs = [
                TxOut(
                    value=py_out.value,
                    script_pubkey=bytes(py_out.script_pubkey),
                )
                for py_out in py_tx.outputs
            ]
            transactions.append(Transaction(
                txid=bytes(py_tx.txid),
                version=py_tx.version,
                locktime=py_tx.locktime,
                inputs=inputs,
                outputs=outputs,
            ))
        
        return Block(
            version=py_block.version,
            prev_blockhash=bytes(py_block.prev_blockhash),
            merkle_root=bytes(py_block.merkle_root),
            timestamp=py_block.timestamp,
            bits=py_block.bits,
            nonce=py_block.nonce,
            transactions=transactions,
            hash=bytes(py_block.hash),
        )
