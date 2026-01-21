"""
Bitcoin P2P protocol message types.

This module implements Bitcoin's peer-to-peer protocol message types
for network communication between nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, TYPE_CHECKING
import struct
import hashlib
import time

if TYPE_CHECKING:
    from ouroboros.database import Block, Transaction

# Bitcoin P2P magic bytes for different networks
MAGIC_MAINNET = 0xD9B4BEF9
MAGIC_TESTNET = 0x0709110B
MAGIC_REGTEST = 0xDAB5BFFA
MAGIC_SIGNET = 0x40CF030A

# Inventory type constants
INV_TYPE_ERROR = 0
INV_TYPE_TX = 1
INV_TYPE_BLOCK = 2
INV_TYPE_FILTERED_BLOCK = 3
INV_TYPE_COMPACT_BLOCK = 4


def get_magic(network: str) -> int:
    """Get magic bytes for a network"""
    network_map = {
        "mainnet": MAGIC_MAINNET,
        "testnet": MAGIC_TESTNET,
        "regtest": MAGIC_REGTEST,
        "signet": MAGIC_SIGNET,
    }
    return network_map.get(network.lower(), MAGIC_MAINNET)


def calculate_checksum(payload: bytes) -> bytes:
    """Calculate message checksum (first 4 bytes of double SHA256)"""
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def encode_varint(value: int) -> bytes:
    """Encode variable-length integer"""
    if value < 0xfd:
        return struct.pack('<B', value)
    elif value <= 0xffff:
        return struct.pack('<BH', 0xfd, value)
    elif value <= 0xffffffff:
        return struct.pack('<BI', 0xfe, value)
    else:
        return struct.pack('<BQ', 0xff, value)


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode variable-length integer, returns (value, bytes_consumed)"""
    if offset >= len(data):
        raise ValueError("Not enough data for varint")
    
    first_byte = data[offset]
    
    if first_byte < 0xfd:
        return first_byte, 1
    elif first_byte == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<H', data[offset + 1:offset + 3])[0]
        return value, 3
    elif first_byte == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<I', data[offset + 1:offset + 5])[0]
        return value, 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<Q', data[offset + 1:offset + 9])[0]
        return value, 9


def command_to_bytes(command: str) -> bytes:
    """Convert command string to 12-byte null-padded bytes"""
    cmd_bytes = command.encode('ascii')
    if len(cmd_bytes) > 12:
        raise ValueError(f"Command too long: {command}")
    padded = cmd_bytes + b'\x00' * (12 - len(cmd_bytes))
    return padded


@dataclass
class NetworkMessage:
    """Base Bitcoin network message"""
    command: str
    payload: bytes
    magic: int = MAGIC_MAINNET
    
    def serialize(self) -> bytes:
        """
        Serialize message to bytes.
        
        Format:
        - Magic (4 bytes, little-endian)
        - Command (12 bytes, null-padded)
        - Payload length (4 bytes, little-endian)
        - Checksum (4 bytes, first 4 bytes of double SHA256)
        - Payload
        """
        checksum = calculate_checksum(self.payload)
        cmd_bytes = command_to_bytes(self.command)
        
        data = struct.pack('<I', self.magic)  # Magic
        data += cmd_bytes  # Command (12 bytes)
        data += struct.pack('<I', len(self.payload))  # Payload length
        data += checksum  # Checksum (4 bytes)
        data += self.payload  # Payload
        
        return data
    
    @classmethod
    def deserialize(cls, data: bytes, network: str = "mainnet") -> 'NetworkMessage':
        """
        Deserialize from bytes.
        
        Args:
            data: Raw message bytes
            network: Network name for magic byte validation
            
        Returns:
            NetworkMessage instance
            
        Raises:
            ValueError: If message format is invalid
        """
        if len(data) < 24:
            raise ValueError("Message too short (minimum 24 bytes)")
        
        magic = struct.unpack('<I', data[0:4])[0]
        expected_magic = get_magic(network)
        if magic != expected_magic:
            raise ValueError(
                f"Invalid magic bytes: expected {expected_magic:08x}, got {magic:08x}"
            )
        
        # Command (12 bytes, null-padded)
        cmd_bytes = data[4:16].rstrip(b'\x00')
        command = cmd_bytes.decode('ascii')
        
        # Payload length
        payload_size = struct.unpack('<I', data[16:20])[0]
        
        # Checksum
        checksum = data[20:24]
        
        # Payload
        if len(data) < 24 + payload_size:
            raise ValueError(f"Not enough data for payload: need {24 + payload_size}, got {len(data)}")
        
        payload = data[24:24 + payload_size]
        
        # Verify checksum
        calculated_checksum = calculate_checksum(payload)
        if calculated_checksum != checksum:
            raise ValueError(
                f"Invalid checksum: expected {checksum.hex()}, got {calculated_checksum.hex()}"
            )
        
        return cls(command=command, payload=payload, magic=magic)
    
    def checksum(self) -> bytes:
        """Calculate message checksum"""
        return calculate_checksum(self.payload)


@dataclass
class NetworkAddress:
    """Bitcoin network address (IP + port)"""
    services: int = 0
    ip: bytes = b'\x00' * 16  # IPv6 (IPv4 mapped to IPv6)
    port: int = 0
    
    @classmethod
    def from_ipv4(cls, ip: str, port: int, services: int = 1) -> 'NetworkAddress':
        """
        Create network address from IPv4 address.
        
        Args:
            ip: IPv4 address as string (e.g., "192.168.1.1")
            port: Port number
            services: Services flags
            
        Returns:
            NetworkAddress instance with IPv4-mapped IPv6 address
        """
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address: {ip}")
        
        ipv4_bytes = bytes([int(p) for p in parts])
        # Create IPv4-mapped IPv6 address (::ffff:ipv4)
        ipv6_bytes = b'\x00' * 10 + b'\xff\xff' + ipv4_bytes
        
        return cls(services=services, ip=ipv6_bytes, port=port)
    
    def serialize(self) -> bytes:
        """Serialize network address"""
        data = struct.pack('<Q', self.services)  # Services (8 bytes)
        data += self.ip  # IP (16 bytes)
        data += struct.pack('>H', self.port)  # Port (2 bytes, big-endian)
        return data
    
    @classmethod
    def from_payload(cls, data: bytes, offset: int = 0) -> Tuple['NetworkAddress', int]:
        """Deserialize network address, returns (address, bytes_consumed)"""
        if len(data) < offset + 26:
            raise ValueError("Not enough data for network address")
        
        services = struct.unpack('<Q', data[offset:offset + 8])[0]
        ip = data[offset + 8:offset + 24]
        port = struct.unpack('>H', data[offset + 24:offset + 26])[0]
        
        return cls(services=services, ip=ip, port=port), 26


@dataclass
class VersionMessage:
    """Version message for handshake"""
    version: int = 70015
    services: int = 0
    timestamp: int = 0
    addr_recv: NetworkAddress = field(default_factory=lambda: NetworkAddress())
    addr_from: NetworkAddress = field(default_factory=lambda: NetworkAddress())
    nonce: int = 0
    user_agent: str = "/bitcoin-hybrid:0.1.0/"
    start_height: int = 0
    relay: bool = True
    
    def __post_init__(self):
        """Set default timestamp if not provided"""
        if self.timestamp == 0:
            self.timestamp = int(time.time())
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.serialize_payload()
        return NetworkMessage(command="version", payload=payload, magic=get_magic(network))
    
    def serialize_payload(self) -> bytes:
        """Serialize version message payload"""
        data = struct.pack('<i', self.version)  # Version (4 bytes)
        data += struct.pack('<Q', self.services)  # Services (8 bytes)
        data += struct.pack('<q', self.timestamp)  # Timestamp (8 bytes)
        data += self.addr_recv.serialize()  # Address receiving (26 bytes)
        data += self.addr_from.serialize()  # Address from (26 bytes)
        data += struct.pack('<Q', self.nonce)  # Nonce (8 bytes)
        
        # User agent (varint length + string)
        user_agent_bytes = self.user_agent.encode('utf-8')
        data += encode_varint(len(user_agent_bytes))
        data += user_agent_bytes
        
        data += struct.pack('<i', self.start_height)  # Start height (4 bytes)
        
        # Relay (1 byte, optional in newer versions)
        if self.version >= 70001:
            data += struct.pack('<B', 1 if self.relay else 0)
        
        return data
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'VersionMessage':
        """Parse from payload"""
        offset = 0
        
        # Version (4 bytes)
        version = struct.unpack('<i', payload[offset:offset + 4])[0]
        offset += 4
        
        # Services (8 bytes)
        services = struct.unpack('<Q', payload[offset:offset + 8])[0]
        offset += 8
        
        # Timestamp (8 bytes)
        timestamp = struct.unpack('<q', payload[offset:offset + 8])[0]
        offset += 8
        
        # Address receiving (26 bytes)
        addr_recv, consumed = NetworkAddress.from_payload(payload, offset)
        offset += consumed
        
        # Address from (26 bytes)
        addr_from, consumed = NetworkAddress.from_payload(payload, offset)
        offset += consumed
        
        # Nonce (8 bytes)
        nonce = struct.unpack('<Q', payload[offset:offset + 8])[0]
        offset += 8
        
        # User agent (varint + string)
        user_agent_len, consumed = decode_varint(payload, offset)
        offset += consumed
        user_agent = payload[offset:offset + user_agent_len].decode('utf-8')
        offset += user_agent_len
        
        # Start height (4 bytes)
        start_height = struct.unpack('<i', payload[offset:offset + 4])[0]
        offset += 4
        
        # Relay (1 byte, optional)
        relay = True
        if offset < len(payload) and version >= 70001:
            relay = struct.unpack('<B', payload[offset:offset + 1])[0] != 0
        
        return cls(
            version=version,
            services=services,
            timestamp=timestamp,
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=nonce,
            user_agent=user_agent,
            start_height=start_height,
            relay=relay
        )


@dataclass
class InvMessage:
    """Inventory message (announces blocks/transactions)"""
    inventory: List[Tuple[int, bytes]]  # (type, hash) pairs
    # type: 1=tx, 2=block, 3=filtered_block, 4=compact_block
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.serialize_payload()
        return NetworkMessage(command="inv", payload=payload, magic=get_magic(network))
    
    def serialize_payload(self) -> bytes:
        """Serialize inventory message payload"""
        data = encode_varint(len(self.inventory))  # Count
        
        # Inventory items (4 bytes type + 32 bytes hash each)
        for inv_type, inv_hash in self.inventory:
            data += struct.pack('<I', inv_type)  # Type (4 bytes)
            if len(inv_hash) != 32:
                raise ValueError(f"Invalid hash length: {len(inv_hash)}, expected 32")
            data += inv_hash  # Hash (32 bytes)
        
        return data
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'InvMessage':
        """Parse from payload"""
        offset = 0
        
        # Count (varint)
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        
        # Limit to 50k items for safety
        if count > 50000:
            raise ValueError(f"Inventory count too large: {count}")
        
        inventory = []
        for _ in range(count):
            if offset + 36 > len(payload):
                raise ValueError("Not enough data for inventory item")
            
            inv_type = struct.unpack('<I', payload[offset:offset + 4])[0]
            offset += 4
            inv_hash = payload[offset:offset + 32]
            offset += 32
            
            inventory.append((inv_type, inv_hash))
        
        return cls(inventory=inventory)


@dataclass
class GetDataMessage:
    """Request blocks/transactions"""
    inventory: List[Tuple[int, bytes]]
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        # Same format as InvMessage
        inv_msg = InvMessage(self.inventory)
        payload = inv_msg.serialize_payload()
        return NetworkMessage(command="getdata", payload=payload, magic=get_magic(network))
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'GetDataMessage':
        """Parse from payload"""
        inv_msg = InvMessage.from_payload(payload)
        return cls(inventory=inv_msg.inventory)


@dataclass
class BlockMessage:
    """Block delivery"""
    block: 'Block'
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        # Note: Block serialization is complex and requires full Bitcoin protocol encoding
        # For now, this is a placeholder that would need the Rust layer
        raise NotImplementedError(
            "Block serialization requires full Bitcoin protocol encoding. "
            "Use Rust BlockWrapper for proper serialization."
        )
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'BlockMessage':
        """Parse from payload"""
        # Note: Block deserialization is complex and requires full Bitcoin protocol decoding
        # For now, this is a placeholder that would need the Rust layer
        raise NotImplementedError(
            "Block deserialization requires full Bitcoin protocol decoding. "
            "Use Rust BlockWrapper for proper deserialization."
        )


@dataclass
class TxMessage:
    """Transaction delivery"""
    transaction: 'Transaction'
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.transaction.serialize()
        return NetworkMessage(command="tx", payload=payload, magic=get_magic(network))
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'TxMessage':
        """
        Deserialize transaction message from payload.
        
        Format:
        - version (4 bytes, little-endian)
        - flags/inputs count (varint or segwit flag)
        - inputs (variable)
          - prev_txid (32 bytes)
          - prev_vout (4 bytes, little-endian)
          - script_sig length (varint)
          - script_sig (variable)
          - sequence (4 bytes, little-endian)
        - outputs (variable)
          - value (8 bytes, little-endian)
          - script_pubkey length (varint)
          - script_pubkey (variable)
        - locktime (4 bytes, little-endian)
        - witness data (if segwit flag present)
        """
        from ouroboros.database import Transaction, TxIn, TxOut
        
        offset = 0
        
        # Parse version (4 bytes)
        if len(payload) < 4:
            raise ValueError("Payload too short for version")
        version = int.from_bytes(payload[offset:offset+4], byteorder='little', signed=True)
        offset += 4
        
        # Check for segwit flag (0x00, 0x01)
        has_witness = False
        if len(payload) > offset + 2 and payload[offset] == 0x00 and payload[offset+1] == 0x01:
            has_witness = True
            offset += 2
        
        # Parse inputs count (varint)
        if len(payload) <= offset:
            raise ValueError("Payload too short for inputs count")
        inputs_count, varint_size = decode_varint(payload, offset)
        offset += varint_size
        
        # Parse inputs
        inputs = []
        for i in range(inputs_count):
            if len(payload) < offset + 36:  # 32 + 4 minimum
                raise ValueError(f"Payload too short for input {i}")
            
            # prev_txid (32 bytes, reversed for display format)
            prev_txid = payload[offset:offset+32][::-1]  # Reverse for big-endian
            offset += 32
            
            # prev_vout (4 bytes)
            prev_vout = int.from_bytes(payload[offset:offset+4], byteorder='little')
            offset += 4
            
            # script_sig length (varint)
            script_sig_len, varint_size = decode_varint(payload, offset)
            offset += varint_size
            
            # script_sig
            if len(payload) < offset + script_sig_len:
                raise ValueError(f"Payload too short for script_sig in input {i}")
            script_sig = payload[offset:offset+script_sig_len]
            offset += script_sig_len
            
            # sequence (4 bytes)
            if len(payload) < offset + 4:
                raise ValueError(f"Payload too short for sequence in input {i}")
            sequence = int.from_bytes(payload[offset:offset+4], byteorder='little')
            offset += 4
            
            inputs.append(TxIn(
                prev_txid=prev_txid,
                prev_vout=prev_vout,
                script_sig=script_sig,
                sequence=sequence
            ))
        
        # Parse outputs count (varint)
        if len(payload) <= offset:
            raise ValueError("Payload too short for outputs count")
        outputs_count, varint_size = decode_varint(payload, offset)
        offset += varint_size
        
        # Parse outputs
        outputs = []
        for i in range(outputs_count):
            if len(payload) < offset + 8:  # value minimum
                raise ValueError(f"Payload too short for value in output {i}")
            
            # value (8 bytes)
            value = int.from_bytes(payload[offset:offset+8], byteorder='little')
            offset += 8
            
            # script_pubkey length (varint)
            script_pubkey_len, varint_size = decode_varint(payload, offset)
            offset += varint_size
            
            # script_pubkey
            if len(payload) < offset + script_pubkey_len:
                raise ValueError(f"Payload too short for script_pubkey in output {i}")
            script_pubkey = payload[offset:offset+script_pubkey_len]
            offset += script_pubkey_len
            
            outputs.append(TxOut(
                value=value,
                script_pubkey=script_pubkey
            ))
        
        # Parse witness data if present (for SegWit transactions)
        # Note: We parse witness data but don't store it in Transaction object yet
        # as it's not in the current Transaction dataclass structure
        if has_witness:
            for i in range(inputs_count):
                # Witness stack count (varint)
                if len(payload) <= offset:
                    raise ValueError(f"Payload too short for witness stack count in input {i}")
                stack_count, varint_size = decode_varint(payload, offset)
                offset += varint_size
                
                # Witness stack items
                for j in range(stack_count):
                    item_len, varint_size = decode_varint(payload, offset)
                    offset += varint_size
                    if len(payload) < offset + item_len:
                        raise ValueError(f"Payload too short for witness item {j} in input {i}")
                    # Skip witness item data (not storing for now)
                    offset += item_len
        
        # Parse locktime (4 bytes)
        if len(payload) < offset + 4:
            raise ValueError("Payload too short for locktime")
        locktime = int.from_bytes(payload[offset:offset+4], byteorder='little')
        offset += 4
        
        # Create Transaction object
        # Note: Transaction requires txid which we calculate from the serialized transaction
        # For now, we'll create it with a placeholder txid and let it be calculated later
        # The actual txid should be calculated from the transaction hash
        transaction = Transaction(
            txid=bytes(32),  # Placeholder - should be calculated from transaction hash
            version=version,
            locktime=locktime,
            inputs=inputs,
            outputs=outputs
        )
        
        # Calculate actual txid from transaction
        # Transaction ID is double SHA256 of the transaction (without witness data)
        # For now, we'll calculate it from the serialized version without witness
        # Note: This is a simplified calculation - full txid requires proper serialization
        import hashlib
        tx_bytes = transaction.serialize()
        txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        transaction.txid = txid
        
        return cls(transaction=transaction)


@dataclass
class GetHeadersMessage:
    """Request block headers"""
    version: int = 70015
    locator_hashes: List[bytes] = field(default_factory=list)
    hash_stop: bytes = b'\x00' * 32
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.serialize_payload()
        return NetworkMessage(command="getheaders", payload=payload, magic=get_magic(network))
    
    def serialize_payload(self) -> bytes:
        """Serialize getheaders message payload"""
        data = struct.pack('<i', self.version)  # Version (4 bytes)
        data += encode_varint(len(self.locator_hashes))  # Hash count
        
        # Locator hashes (32 bytes each)
        for hash_bytes in self.locator_hashes:
            if len(hash_bytes) != 32:
                raise ValueError(f"Invalid hash length: {len(hash_bytes)}, expected 32")
            data += hash_bytes
        
        # Hash stop (32 bytes)
        if len(self.hash_stop) != 32:
            raise ValueError(f"Invalid hash_stop length: {len(self.hash_stop)}, expected 32")
        data += self.hash_stop
        
        return data
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'GetHeadersMessage':
        """Parse from payload"""
        offset = 0
        
        # Version (4 bytes)
        version = struct.unpack('<i', payload[offset:offset + 4])[0]
        offset += 4
        
        # Hash count (varint)
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        
        # Limit to 101 hashes (Bitcoin protocol limit)
        if count > 101:
            raise ValueError(f"Too many locator hashes: {count}")
        
        # Locator hashes
        locator_hashes = []
        for _ in range(count):
            if offset + 32 > len(payload):
                raise ValueError("Not enough data for locator hash")
            locator_hashes.append(payload[offset:offset + 32])
            offset += 32
        
        # Hash stop (32 bytes)
        if offset + 32 > len(payload):
            raise ValueError("Not enough data for hash_stop")
        hash_stop = payload[offset:offset + 32]
        
        return cls(
            version=version,
            locator_hashes=locator_hashes,
            hash_stop=hash_stop
        )


@dataclass
class BlockHeader:
    """Block header representation"""
    version: int
    prev_blockhash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    
    def serialize(self) -> bytes:
        """Serialize block header (80 bytes)"""
        data = struct.pack('<i', self.version)  # Version (4 bytes)
        data += self.prev_blockhash  # Previous block hash (32 bytes)
        data += self.merkle_root  # Merkle root (32 bytes)
        data += struct.pack('<I', self.timestamp)  # Timestamp (4 bytes)
        data += struct.pack('<I', self.bits)  # Bits (4 bytes)
        data += struct.pack('<I', self.nonce)  # Nonce (4 bytes)
        return data
    
    @classmethod
    def from_payload(cls, data: bytes, offset: int = 0) -> Tuple['BlockHeader', int]:
        """Deserialize block header, returns (header, bytes_consumed)"""
        if len(data) < offset + 80:
            raise ValueError("Not enough data for block header")
        
        version = struct.unpack('<i', data[offset:offset + 4])[0]
        prev_blockhash = data[offset + 4:offset + 36]
        merkle_root = data[offset + 36:offset + 68]
        timestamp = struct.unpack('<I', data[offset + 68:offset + 72])[0]
        bits = struct.unpack('<I', data[offset + 72:offset + 76])[0]
        nonce = struct.unpack('<I', data[offset + 76:offset + 80])[0]
        
        return cls(
            version=version,
            prev_blockhash=prev_blockhash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce
        ), 80


@dataclass
class HeadersMessage:
    """Block headers delivery"""
    headers: List[BlockHeader]
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.serialize_payload()
        return NetworkMessage(command="headers", payload=payload, magic=get_magic(network))
    
    def serialize_payload(self) -> bytes:
        """Serialize headers message payload"""
        data = encode_varint(len(self.headers))  # Count
        
        # Headers (80 bytes header + 1 byte tx_count each)
        for header in self.headers:
            data += header.serialize()  # Header (80 bytes)
            data += b'\x00'  # Transaction count (always 0 for headers message)
        
        return data
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'HeadersMessage':
        """Parse from payload"""
        offset = 0
        
        # Count (varint)
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        
        # Limit to 2000 headers (Bitcoin protocol limit)
        if count > 2000:
            raise ValueError(f"Too many headers: {count}")
        
        headers = []
        for _ in range(count):
            header, consumed = BlockHeader.from_payload(payload, offset)
            offset += consumed
            
            # Skip transaction count byte (should be 0)
            if offset >= len(payload):
                raise ValueError("Not enough data for tx_count byte")
            tx_count = payload[offset]
            offset += 1
            
            if tx_count != 0:
                raise ValueError(f"Invalid tx_count in headers message: {tx_count}")
            
            headers.append(header)
        
        return cls(headers=headers)


@dataclass
class PingMessage:
    """Ping message"""
    nonce: int
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = struct.pack('<Q', self.nonce)  # Nonce (8 bytes)
        return NetworkMessage(command="ping", payload=payload, magic=get_magic(network))
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'PingMessage':
        """Parse from payload"""
        if len(payload) < 8:
            raise ValueError("Not enough data for ping nonce")
        nonce = struct.unpack('<Q', payload[0:8])[0]
        return cls(nonce=nonce)


@dataclass
class PongMessage:
    """Pong message"""
    nonce: int
    
    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = struct.pack('<Q', self.nonce)  # Nonce (8 bytes)
        return NetworkMessage(command="pong", payload=payload, magic=get_magic(network))
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'PongMessage':
        """Parse from payload"""
        if len(payload) < 8:
            raise ValueError("Not enough data for pong nonce")
        nonce = struct.unpack('<Q', payload[0:8])[0]
        return cls(nonce=nonce)
