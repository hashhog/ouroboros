"""
Python wrapper for blockchain database operations.

This module provides a high-level Python interface to the Rust blockchain database
implementation, allowing Python code to interact with the blockchain storage layer.
"""

from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass
import sync  # Rust extension module


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
    
    def hash(self) -> bytes:
        """Compute block hash"""
        return self.hash
    
    def serialize(self) -> bytes:
        """Serialize to bytes"""
        # This would serialize the block to Bitcoin protocol format
        # For now, return NotImplemented as it requires full BlockWrapper reconstruction
        raise NotImplementedError("Block serialization requires Rust BlockWrapper")
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Block':
        """Deserialize from bytes"""
        # This would deserialize from Bitcoin protocol format
        # For now, return NotImplemented as it requires BitcoinDeserialize
        raise NotImplementedError("Block deserialization requires Rust BitcoinDeserialize")


@dataclass
class Transaction:
    """Bitcoin transaction representation"""
    txid: bytes
    version: int
    locktime: int
    inputs: List['TxIn']
    outputs: List['TxOut']
    
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
            "Use Rust API directly via BlockchainDB.batch_update_utxos()"
        )
    
    def get_best_block(self) -> Tuple[bytes, int]:
        """
        Get chain tip.
        
        Returns:
            Tuple of (block_hash, height)
        """
        hash_bytes, height = self._db.get_best_block()
        return (bytes(hash_bytes), height)
    
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
