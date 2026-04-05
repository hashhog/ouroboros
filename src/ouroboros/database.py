"""
Python wrapper for blockchain database operations.

This module provides a high-level Python interface to the Rust blockchain database
implementation, allowing Python code to interact with the blockchain storage layer.
"""

from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
import sync  # Rust extension module (required)
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
        """Serialize block to Bitcoin wire format (80-byte header + tx list)."""
        from ouroboros.p2p_messages import encode_varint
        
        data = bytearray()
        
        # Serialize header (80 bytes)
        # Version (4 bytes)
        data.extend(self.version.to_bytes(4, 'little', signed=True))
        
        # Previous block hash (32 bytes, already in internal/wire byte order)
        data.extend(self.prev_blockhash)

        # Merkle root (32 bytes, already in internal/wire byte order)
        data.extend(self.merkle_root)
        
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
        """Deserialize a block from Bitcoin wire format.

        Raises ValueError if data is invalid or too short.
        """
        from ouroboros.p2p_messages import decode_varint, TxMessage
        
        offset = 0
        
        if len(data) < 80:  # Minimum header size
            raise ValueError("Block data too short for header")
        
        # Parse header (80 bytes)
        version = int.from_bytes(data[offset:offset+4], byteorder='little', signed=True)
        offset += 4
        
        prev_blockhash = data[offset:offset+32]  # Internal (little-endian) byte order — matches DB
        offset += 32

        merkle_root = data[offset:offset+32]  # Internal (little-endian) byte order
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

                # Use the exact byte count consumed by the parser (including
                # segwit marker, flag, and witness data) so that we advance
                # past the full wire-format transaction.
                tx_size = getattr(tx_msg, 'bytes_consumed', None)
                if tx_size is None:
                    # Fallback: non-witness serialization (may be wrong for segwit)
                    tx_size = len(tx.serialize())

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
        block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()  # Internal byte order — matches DB
        
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
    has_witness: bool = False  # True if SegWit (marker 0x00, flag 0x01)
    
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

    def serialize_with_witness(self) -> bytes:
        """
        Serialize transaction including witness (SegWit wire format).
        Used for wtxid: SHA256D of this equals witness txid for SegWit txs.
        """
        data = bytearray()
        data.extend(self.version.to_bytes(4, 'little', signed=True))
        if self.has_witness:
            data.extend(b'\x00\x01')  # marker, flag
        data.extend(self._encode_varint(len(self.inputs)))
        for tx_in in self.inputs:
            data.extend(tx_in.prev_txid)
            data.extend(tx_in.prev_vout.to_bytes(4, 'little'))
            data.extend(self._encode_varint(len(tx_in.script_sig)))
            data.extend(tx_in.script_sig)
            data.extend(tx_in.sequence.to_bytes(4, 'little'))
        data.extend(self._encode_varint(len(self.outputs)))
        for tx_out in self.outputs:
            data.extend(tx_out.value.to_bytes(8, 'little'))
            data.extend(self._encode_varint(len(tx_out.script_pubkey)))
            data.extend(tx_out.script_pubkey)
        if self.has_witness:
            for tx_in in self.inputs:
                witness = tx_in.witness or []
                data.extend(self._encode_varint(len(witness)))
                for item in witness:
                    data.extend(self._encode_varint(len(item)))
                    data.extend(item)
        data.extend(self.locktime.to_bytes(4, 'little'))
        return bytes(data)

    def get_wtxid(self) -> bytes:
        """Witness transaction ID: double SHA256 of full serialization including witness."""
        if not self.has_witness:
            return self.get_txid()
        return hashlib.sha256(hashlib.sha256(self.serialize_with_witness()).digest()).digest()
    
    def _encode_varint(self, value: int) -> bytes:
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')
    
    def get_witness_bytes(self) -> int:
        """Total encoded witness size in bytes (0 for non-SegWit)."""
        if not self.has_witness:
            return 0
        total = 0
        for tx_in in self.inputs:
            if tx_in.witness is None:
                continue
            total += len(self._encode_varint(len(tx_in.witness)))
            for item in tx_in.witness:
                total += len(self._encode_varint(len(item))) + len(item)
        return total

    def get_weight(self) -> int:
        """Transaction weight: non-witness bytes × 4 + witness bytes (BIP 141)."""
        non_witness_bytes = len(self.serialize())
        if self.has_witness:
            non_witness_bytes += 2  # marker 0x00 + flag 0x01
        witness_bytes = self.get_witness_bytes()
        return (non_witness_bytes * 4) + witness_bytes
    
    def get_vsize(self) -> int:
        """Virtual size in bytes: ceil(weight / 4)."""
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
    witness: Optional[List[bytes]] = None  # SegWit witness stack; None = non-SegWit


@dataclass
class TxOut:
    """Bitcoin transaction output"""
    value: int
    script_pubkey: bytes


class BlockchainDatabase:
    """Read/write access to blockchain data using Rust backend"""
    
    def __init__(self, data_dir: str):
        self._db = sync.PyBlockchainDB(data_dir)
        self._data_dir = data_dir
    
    def get_block(self, block_hash: bytes) -> Optional[Block]:
        """Look up a block by its 32-byte hash; returns None if not found."""
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        
        py_block = self._db.get_block(block_hash)
        if py_block is None:
            return None
        
        return self._py_block_to_block(py_block)
    
    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Look up a block by height; returns None if not found."""
        py_block = self._db.get_block_by_height(height)
        if py_block is None:
            return None
        
        return self._py_block_to_block(py_block)
    
    def get_utxo(self, txid: bytes, vout: int) -> Optional[Dict[str, Any]]:
        """Fetch a UTXO by outpoint; returns a dict (txid, vout, value, script_pubkey) or None."""
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
            'height': getattr(py_utxo, 'height', None),
        }
    
    def store_block(self, block: Block) -> None:
        """Not implemented — use the Rust API via FastSync or BlockSync instead."""
        raise NotImplementedError(
            "store_block requires BlockWrapper reconstruction. "
            "Use Rust API directly via FastSync.store_block() or BlockSync"
        )
    
    def disconnect_block(self, height: int) -> bytes:
        """
        Disconnect the block at the given height — reverse all UTXO changes.

        For each transaction (processed in reverse order):
          - Outputs created by this block are removed from the UTXO set.
          - Inputs spent by this block are restored from undo data stored
            during ``apply_block()`` (full UTXO serialization in SPENT_CF).
        The chain tip (BEST_BLOCK_HASH / BEST_HEIGHT) is rolled back to the
        previous block.

        Args:
            height: Block height to disconnect.

        Returns:
            The 32-byte hash of the disconnected block.

        Raises:
            RuntimeError: If the block is not found or the Rust API fails.
        """
        return bytes(self._db.disconnect_block(height))

    def recover_from_crash(self) -> bool:
        """
        Check for and recover from a mid-apply crash (two-phase commit).

        If a HEAD_BLOCKS marker exists, the previous process crashed during
        ``apply_block()``.  This method rolls back the partial apply by
        disconnecting the incomplete block and restoring the UTXO set.

        Should be called once at startup before any new blocks are applied.
        The Rust ``PyBlockchainDB`` constructor calls this automatically, so
        explicit calls are only needed when using a long-lived database handle
        that was opened before a crash occurred.

        Returns:
            True if a recovery was performed, False if the database was clean.
        """
        return self._db.recover_from_crash()

    def get_tx_index(self, txid: bytes) -> Optional[Tuple[bytes, int, int]]:
        """Look up a confirmed transaction; returns ``(block_hash, height, tx_position)`` or None."""
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        result = self._db.get_tx_index(txid)
        if result is None:
            return None
        block_hash, height, tx_pos = result
        return (bytes(block_hash), height, tx_pos)

    def get_best_block(self) -> Tuple[bytes, int]:
        """Return the current chain tip as ``(block_hash, height)``."""
        hash_bytes, height = self._db.get_best_block()
        return (bytes(hash_bytes), height)

    def update_best_block(self, block_hash: bytes, height: int) -> None:
        """Update the chain tip pointer (used during reorg)."""
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        self._db.update_best_block(block_hash, height)
    
    def get_median_time_past(self, height: int) -> Optional[int]:
        """Median timestamp of the 11 blocks up to *height* (BIP 68 / BIP 113 MTP).

        Uses the Rust backend's lightweight metadata lookup when available,
        falling back to full block deserialization otherwise.
        """
        # Fast path: Rust computes MTP from block metadata (no full block deser)
        if hasattr(self._db, 'get_median_time_past'):
            result = self._db.get_median_time_past(height)
            if result is not None:
                return result

        # Slow fallback: deserialize full blocks
        timestamps = []
        for h in range(max(0, height - 10), height + 1):
            block = self.get_block_by_height(h)
            if block is not None:
                timestamps.append(block.timestamp)
        if not timestamps:
            return None
        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def get_balance(self, address: str, network: str = "mainnet") -> int:
        """Return total balance in satoshis for *address* (sum of matching UTXOs)."""
        from ouroboros.address import address_to_script_pubkey

        script_pubkey = address_to_script_pubkey(address, network)
        return self._balance_for_script_pubkey(script_pubkey)

    def list_unspent_by_address(
        self, address: str, network: str = "mainnet"
    ) -> List[Dict[str, Any]]:
        """Return UTXOs for *address* as a list of dicts (txid, vout, value, script_pubkey)."""
        from ouroboros.address import address_to_script_pubkey

        script_pubkey = address_to_script_pubkey(address, network)
        return self._list_unspent_for_script_pubkey(script_pubkey)

    def _balance_for_script_pubkey(self, script_pubkey: bytes) -> int:
        total = 0
        for utxo in self._iter_matching_utxos(script_pubkey):
            total += utxo["value"]
        return total

    def _list_unspent_for_script_pubkey(self, script_pubkey: bytes) -> List[Dict[str, Any]]:
        return list(self._iter_matching_utxos(script_pubkey))

    def _iter_matching_utxos(self, script_pubkey: bytes):
        try:
            py_utxos = self._db.get_utxos()
        except AttributeError:
            return
        for py_utxo in py_utxos:
            spk = bytes(py_utxo.script_pubkey)
            if spk == script_pubkey:
                txid_hex = py_utxo.txid if isinstance(py_utxo.txid, str) else py_utxo.txid.hex()
                yield {
                    "txid": txid_hex,
                    "vout": py_utxo.vout,
                    "value": py_utxo.value,
                    "script_pubkey": spk,
                }

    def get_block_hash_by_height(self, height: int) -> Optional[bytes]:
        """Return the 32-byte block hash at *height*, or None if not found."""
        try:
            block_hash = self._db.get_block_hash_by_height(height)
            if block_hash is None:
                return None
            return bytes(block_hash)
        except Exception:
            # Fallback: get block by height and extract hash
            block = self.get_block_by_height(height)
            if block:
                h = getattr(block, "hash", None)
            if h is None:
                return None
            return bytes(h() if callable(h) else h)
            return None
    
    def get_chainwork_by_height(self, height: int) -> int:
        """Return cumulative chainwork at *height* (from Rust metadata), or 0 if missing."""
        try:
            cw_bytes = bytes(self._db.get_chainwork_by_height(height))
        except AttributeError:
            # Rust module not yet rebuilt with get_chainwork_by_height
            return 0
        if len(cw_bytes) != 32:
            return 0
        return int.from_bytes(cw_bytes, "big")

    def store_block_chainwork(self, block_hash: bytes, chainwork: int) -> None:
        """Cache chainwork for *block_hash* in memory (fallback when Rust metadata is unavailable)."""
        if not hasattr(self, "_chainwork_cache"):
            self._chainwork_cache: Dict[bytes, int] = {}

        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        self._chainwork_cache[block_hash] = chainwork

    def get_block_chainwork(self, block_hash: bytes, height: Optional[int] = None) -> int:
        """Return chainwork for a block; prefers Rust metadata, falls back to in-memory cache."""
        if height is not None:
            persisted = self.get_chainwork_by_height(height)
            if persisted > 0:
                return persisted

        if not hasattr(self, "_chainwork_cache"):
            self._chainwork_cache = {}

        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        return self._chainwork_cache.get(block_hash, 0)
    
    # Pruning (delegated to Rust)

    def prune_blocks_range(self, from_height: int, to_height: int) -> int:
        """Delete raw block data for heights [from_height, to_height].
        Block index (headers/metadata) is preserved. Returns count removed."""
        return self._db.prune_blocks_range(from_height, to_height)

    def prune_block_at_height(self, height: int) -> bool:
        """Delete raw block data at *height*. Returns True if removed."""
        return self._db.prune_block_at_height(height)

    def get_prune_height(self) -> int:
        """Lowest height whose block body is still available (0 = never pruned)."""
        return self._db.get_prune_height()

    def has_block_data(self, height: int) -> bool:
        """True when the full block body exists for *height*."""
        return self._db.has_block_data(height)

    def estimate_blocks_size(self) -> int:
        """Approximate total bytes of all block bodies in RocksDB."""
        return self._db.estimate_blocks_size()

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
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
            hash=bytes(py_block.hash() if callable(getattr(py_block, "hash", None)) else py_block.hash),
            height=getattr(py_block, 'height', None),
        )
