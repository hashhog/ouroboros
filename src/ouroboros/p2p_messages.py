"""
Bitcoin P2P protocol message types.

This module implements Bitcoin's peer-to-peer protocol message types
for network communication between nodes.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ouroboros.database import Block, Transaction

# Bitcoin P2P magic bytes for different networks
MAGIC_MAINNET = 0xD9B4BEF9
MAGIC_TESTNET = 0x0709110B
MAGIC_TESTNET4 = 0x283F161C
MAGIC_REGTEST = 0xDAB5BFFA
MAGIC_SIGNET = 0x40CF030A

# Inventory type constants
INV_TYPE_ERROR = 0
INV_TYPE_TX = 1
INV_TYPE_BLOCK = 2
INV_TYPE_FILTERED_BLOCK = 3
INV_TYPE_COMPACT_BLOCK = 4

# Witness-aware inventory types (SegWit / BIP 339)
MSG_WITNESS_FLAG = 1 << 30           # 0x40000000
MSG_WITNESS_TX = MSG_WITNESS_FLAG | INV_TYPE_TX      # 0x40000001
MSG_WITNESS_BLOCK = MSG_WITNESS_FLAG | INV_TYPE_BLOCK  # 0x40000002
MSG_WTX = 5  # BIP 339 wtxid-based relay

# Service flags (protocol version field)
NODE_NETWORK = 1 << 0           # 0x0001 — full block history
NODE_BLOOM = 1 << 2             # 0x0004 — BIP 111 bloom filters
NODE_WITNESS = 1 << 3           # 0x0008 — SegWit (BIP 144)
NODE_COMPACT_FILTERS = 1 << 6   # 0x0040 — BIP 157/158 compact block filters
NODE_NETWORK_LIMITED = 1 << 10  # 0x0400 — BIP 159 pruned node (last 288 blocks)
NODE_P2P_V2 = 1 << 11          # 0x0800 — BIP 324 encrypted transport


def get_magic(network: str) -> int:
    """Get magic bytes for a network"""
    network_map = {
        "mainnet": MAGIC_MAINNET,
        "testnet": MAGIC_TESTNET,
        "testnet3": MAGIC_TESTNET,
        "testnet4": MAGIC_TESTNET4,
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


_MAX_COMPACT_SIZE = 0x02000000  # Bitcoin Core serialize.h MAX_SIZE


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode variable-length integer (CompactSize), returns (value, bytes_consumed).

    Rejects non-canonical encodings (Core: "non-canonical ReadCompactSize()") and
    values exceeding MAX_SIZE (0x02000000) per Bitcoin Core serialize.h.
    """
    if offset >= len(data):
        raise ValueError("Not enough data for varint")

    first_byte = data[offset]

    if first_byte < 0xfd:
        value = first_byte
        bytes_consumed = 1
    elif first_byte == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<H', data[offset + 1:offset + 3])[0]
        if value < 0xfd:
            raise ValueError(f"Non-canonical CompactSize: 0xfd prefix with value {value} < 0xfd")
        bytes_consumed = 3
    elif first_byte == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<I', data[offset + 1:offset + 5])[0]
        if value < 0x10000:
            raise ValueError(f"Non-canonical CompactSize: 0xfe prefix with value {value} < 0x10000")
        bytes_consumed = 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError("Not enough data for varint")
        value = struct.unpack('<Q', data[offset + 1:offset + 9])[0]
        if value < 0x100000000:
            raise ValueError(f"Non-canonical CompactSize: 0xff prefix with value {value} < 0x100000000")
        bytes_consumed = 9

    if value > _MAX_COMPACT_SIZE:
        raise ValueError(f"CompactSize value {value} exceeds MAX_SIZE ({_MAX_COMPACT_SIZE})")
    return value, bytes_consumed


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

        data = struct.pack('<I', self.magic)
        data += cmd_bytes
        data += struct.pack('<I', len(self.payload))
        data += checksum
        data += self.payload

        return data

    @classmethod
    def deserialize(cls, data: bytes, network: str = "mainnet") -> NetworkMessage:
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

        cmd_bytes = data[4:16].rstrip(b'\x00')
        command = cmd_bytes.decode('ascii')

        payload_size = struct.unpack('<I', data[16:20])[0]

        checksum = data[20:24]

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
    def from_ipv4(cls, ip: str, port: int, services: int = 1) -> NetworkAddress:
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
    def from_payload(cls, data: bytes, offset: int = 0) -> tuple[NetworkAddress, int]:
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
    def from_payload(cls, payload: bytes) -> VersionMessage:
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
    inventory: list[tuple[int, bytes]]  # (type, hash) pairs
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
    def from_payload(cls, payload: bytes) -> InvMessage:
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
    inventory: list[tuple[int, bytes]]

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        # Same format as InvMessage
        inv_msg = InvMessage(self.inventory)
        payload = inv_msg.serialize_payload()
        return NetworkMessage(command="getdata", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetDataMessage:
        """Parse from payload"""
        inv_msg = InvMessage.from_payload(payload)
        return cls(inventory=inv_msg.inventory)


@dataclass
class BlockMessage:
    """Block delivery"""
    block: Block

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.block.serialize()
        return NetworkMessage(command="block", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> BlockMessage:
        """Parse from payload"""
        from ouroboros.database import Block
        block = Block.deserialize(payload)
        return cls(block=block)


@dataclass
class TxMessage:
    """Transaction delivery"""
    transaction: Transaction

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Convert to network message"""
        payload = self.transaction.serialize()
        return NetworkMessage(command="tx", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> TxMessage:
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

        # Parse version (4 bytes).  Core treats CTransaction::version as a
        # uint32_t on the wire (primitives/transaction.h), so read it
        # UNSIGNED and keep it consistent with serialize() — otherwise a
        # negative version (e.g. 0xFFFFFFFF) round-trips to -1 and crashes
        # the unsigned serializer used to compute the txid below.
        if len(payload) < 4:
            raise ValueError("Payload too short for version")
        version = int.from_bytes(payload[offset:offset+4], byteorder='little', signed=False)
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

            # prev_txid (32 bytes, internal byte order — same as wire)
            prev_txid = payload[offset:offset+32]
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
                sequence=sequence,
                witness=None,
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
        if has_witness:
            for i in range(inputs_count):
                # Witness stack count (varint)
                if len(payload) <= offset:
                    raise ValueError(f"Payload too short for witness stack count in input {i}")
                stack_count, varint_size = decode_varint(payload, offset)
                offset += varint_size

                # Witness stack items
                witness_stack = []
                for j in range(stack_count):
                    item_len, varint_size = decode_varint(payload, offset)
                    offset += varint_size
                    if len(payload) < offset + item_len:
                        raise ValueError(f"Payload too short for witness item {j} in input {i}")
                    witness_stack.append(payload[offset:offset + item_len])
                    offset += item_len
                # Update input with witness data
                inputs[i] = TxIn(
                    prev_txid=inputs[i].prev_txid,
                    prev_vout=inputs[i].prev_vout,
                    script_sig=inputs[i].script_sig,
                    sequence=inputs[i].sequence,
                    witness=witness_stack,
                )
            # BIP144 / Core primitives/transaction.h:228-231:
            # It's illegal to encode witnesses when all witness stacks are empty.
            # Core throws "Superfluous witness record" in this case.
            if not any(inp.witness for inp in inputs):
                raise ValueError("Superfluous witness record")

        # Parse locktime (4 bytes)
        if len(payload) < offset + 4:
            raise ValueError("Payload too short for locktime")
        locktime = int.from_bytes(payload[offset:offset+4], byteorder='little')
        offset += 4

        # Create Transaction object
        transaction = Transaction(
            txid=bytes(32),  # Placeholder - calculated below from non-witness serialization
            version=version,
            locktime=locktime,
            inputs=inputs,
            outputs=outputs,
            has_witness=has_witness,
        )

        # Calculate actual txid from transaction
        # Transaction ID is double SHA256 of the non-witness serialization
        import hashlib
        tx_bytes = transaction.serialize()
        txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
        transaction.txid = txid

        # Store the wire-format byte count so callers (like Block.deserialize)
        # can advance their offset correctly past witness data.
        result = cls(transaction=transaction)
        result.bytes_consumed = offset
        return result


@dataclass
class GetHeadersMessage:
    """Request block headers"""
    version: int = 70015
    locator_hashes: list[bytes] = field(default_factory=list)
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
    def from_payload(cls, payload: bytes) -> GetHeadersMessage:
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
    def from_payload(cls, data: bytes, offset: int = 0) -> tuple[BlockHeader, int]:
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
    headers: list[BlockHeader]

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
    def from_payload(cls, payload: bytes) -> HeadersMessage:
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
    def from_payload(cls, payload: bytes) -> PingMessage:
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
    def from_payload(cls, payload: bytes) -> PongMessage:
        """Parse from payload"""
        if len(payload) < 8:
            raise ValueError("Not enough data for pong nonce")
        nonce = struct.unpack('<Q', payload[0:8])[0]
        return cls(nonce=nonce)


# BIP 152 Compact Block messages


@dataclass
class SendCmpctMessage:
    """
    ``sendcmpct`` — negotiate compact block support.

    Sent after the version handshake.
    announce: True = high-bandwidth mode (peer sends cmpctblock unsolicited)
    version: compact-block protocol version (1 or 2; 2 uses wtxid for SipHash)
    """
    announce: bool = False
    version: int = 2

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<BQ', int(self.announce), self.version)
        return NetworkMessage(
            command="sendcmpct", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SendCmpctMessage:
        if len(payload) < 9:
            raise ValueError("sendcmpct payload too short")
        announce = bool(payload[0])
        version = struct.unpack('<Q', payload[1:9])[0]
        return cls(announce=announce, version=version)


@dataclass
class CmpctBlockMessage:
    """``cmpctblock`` — compact block announcement."""
    payload_bytes: bytes

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="cmpctblock", payload=self.payload_bytes,
            magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> CmpctBlockMessage:
        return cls(payload_bytes=payload)

    def to_compact_block(self):
        from ouroboros.compact_blocks import CompactBlock
        return CompactBlock.deserialize(self.payload_bytes)


@dataclass
class GetBlockTxnMessage:
    """``getblocktxn`` — request missing transactions."""
    payload_bytes: bytes

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="getblocktxn", payload=self.payload_bytes,
            magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetBlockTxnMessage:
        return cls(payload_bytes=payload)

    def to_request(self):
        from ouroboros.compact_blocks import BlockTransactionsRequest
        return BlockTransactionsRequest.deserialize(self.payload_bytes)


@dataclass
class BlockTxnMessage:
    """``blocktxn`` — response with missing transactions."""
    payload_bytes: bytes

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="blocktxn", payload=self.payload_bytes,
            magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> BlockTxnMessage:
        return cls(payload_bytes=payload)

    def to_block_transactions(self):
        from ouroboros.compact_blocks import BlockTransactions
        return BlockTransactions.deserialize(self.payload_bytes)


# ---------------------------------------------------------------------------
# BIP 157 / 158 compact-filter P2P messages
# ---------------------------------------------------------------------------

# BIP-157 protocol limits — match Bitcoin Core src/net_processing.cpp.
MAX_GETCFILTERS_SIZE = 1000      # max blocks per getcfilters request
MAX_GETCFHEADERS_SIZE = 2000     # max blocks per getcfheaders request
CFCHECKPT_INTERVAL = 1000        # cfcheckpt header spacing


@dataclass
class GetCFiltersMessage:
    """
    ``getcfilters`` (BIP 157) — request a range of compact filters.

    Wire format:
        filter_type    (1 byte)
        start_height   (uint32, little-endian)
        stop_hash      (32 bytes, internal byte order)
    """
    filter_type: int = 0
    start_height: int = 0
    stop_hash: bytes = b'\x00' * 32

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = (
            struct.pack('<B', self.filter_type & 0xFF)
            + struct.pack('<I', self.start_height & 0xFFFFFFFF)
            + bytes(self.stop_hash)
        )
        return NetworkMessage(
            command="getcfilters", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetCFiltersMessage:
        if len(payload) < 1 + 4 + 32:
            raise ValueError("getcfilters payload too short")
        filter_type = payload[0]
        start_height = struct.unpack('<I', payload[1:5])[0]
        stop_hash = bytes(payload[5:5 + 32])
        return cls(
            filter_type=filter_type,
            start_height=start_height,
            stop_hash=stop_hash,
        )


@dataclass
class CFilterMessage:
    """
    ``cfilter`` (BIP 157) — single compact filter response.

    Wire format:
        filter_type     (1 byte)
        block_hash      (32 bytes)
        filter_bytes    (CompactSize-prefixed byte vector)
    """
    filter_type: int = 0
    block_hash: bytes = b'\x00' * 32
    filter_bytes: bytes = b''

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = (
            struct.pack('<B', self.filter_type & 0xFF)
            + bytes(self.block_hash)
            + encode_varint(len(self.filter_bytes))
            + bytes(self.filter_bytes)
        )
        return NetworkMessage(
            command="cfilter", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> CFilterMessage:
        if len(payload) < 1 + 32 + 1:
            raise ValueError("cfilter payload too short")
        filter_type = payload[0]
        block_hash = bytes(payload[1:33])
        n, consumed = decode_varint(payload, 33)
        offset = 33 + consumed
        if offset + n > len(payload):
            raise ValueError("cfilter payload truncated")
        filter_bytes = bytes(payload[offset:offset + n])
        return cls(
            filter_type=filter_type,
            block_hash=block_hash,
            filter_bytes=filter_bytes,
        )


@dataclass
class GetCFHeadersMessage:
    """
    ``getcfheaders`` (BIP 157) — request filter headers and filter hashes.

    Same wire format as getcfilters.
    """
    filter_type: int = 0
    start_height: int = 0
    stop_hash: bytes = b'\x00' * 32

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = (
            struct.pack('<B', self.filter_type & 0xFF)
            + struct.pack('<I', self.start_height & 0xFFFFFFFF)
            + bytes(self.stop_hash)
        )
        return NetworkMessage(
            command="getcfheaders", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetCFHeadersMessage:
        if len(payload) < 1 + 4 + 32:
            raise ValueError("getcfheaders payload too short")
        filter_type = payload[0]
        start_height = struct.unpack('<I', payload[1:5])[0]
        stop_hash = bytes(payload[5:5 + 32])
        return cls(
            filter_type=filter_type,
            start_height=start_height,
            stop_hash=stop_hash,
        )


@dataclass
class CFHeadersMessage:
    """
    ``cfheaders`` (BIP 157) — response to getcfheaders.

    Wire format:
        filter_type        (1 byte)
        stop_hash          (32 bytes)
        previous_filter_header (32 bytes)
        filter_hashes      (CompactSize length-prefixed list of 32-byte hashes)
    """
    filter_type: int = 0
    stop_hash: bytes = b'\x00' * 32
    previous_filter_header: bytes = b'\x00' * 32
    filter_hashes: list[bytes] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = bytearray()
        payload.append(self.filter_type & 0xFF)
        payload.extend(bytes(self.stop_hash))
        payload.extend(bytes(self.previous_filter_header))
        payload.extend(encode_varint(len(self.filter_hashes)))
        for h in self.filter_hashes:
            payload.extend(bytes(h))
        return NetworkMessage(
            command="cfheaders", payload=bytes(payload), magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> CFHeadersMessage:
        if len(payload) < 1 + 32 + 32 + 1:
            raise ValueError("cfheaders payload too short")
        filter_type = payload[0]
        stop_hash = bytes(payload[1:33])
        prev_header = bytes(payload[33:65])
        n, consumed = decode_varint(payload, 65)
        offset = 65 + consumed
        if offset + n * 32 > len(payload):
            raise ValueError("cfheaders payload truncated")
        hashes = [bytes(payload[offset + 32 * i:offset + 32 * (i + 1)]) for i in range(n)]
        return cls(
            filter_type=filter_type,
            stop_hash=stop_hash,
            previous_filter_header=prev_header,
            filter_hashes=hashes,
        )


@dataclass
class GetCFCheckptMessage:
    """
    ``getcfcheckpt`` (BIP 157) — request evenly spaced filter headers.

    Wire format:
        filter_type   (1 byte)
        stop_hash     (32 bytes)
    """
    filter_type: int = 0
    stop_hash: bytes = b'\x00' * 32

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<B', self.filter_type & 0xFF) + bytes(self.stop_hash)
        return NetworkMessage(
            command="getcfcheckpt", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetCFCheckptMessage:
        if len(payload) < 1 + 32:
            raise ValueError("getcfcheckpt payload too short")
        filter_type = payload[0]
        stop_hash = bytes(payload[1:33])
        return cls(filter_type=filter_type, stop_hash=stop_hash)


@dataclass
class CFCheckptMessage:
    """
    ``cfcheckpt`` (BIP 157) — response with checkpoint filter headers
    every CFCHECKPT_INTERVAL blocks up to *stop_hash*.

    Wire format:
        filter_type      (1 byte)
        stop_hash        (32 bytes)
        filter_headers   (CompactSize-prefixed list of 32-byte filter headers)
    """
    filter_type: int = 0
    stop_hash: bytes = b'\x00' * 32
    filter_headers: list[bytes] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = bytearray()
        payload.append(self.filter_type & 0xFF)
        payload.extend(bytes(self.stop_hash))
        payload.extend(encode_varint(len(self.filter_headers)))
        for h in self.filter_headers:
            payload.extend(bytes(h))
        return NetworkMessage(
            command="cfcheckpt", payload=bytes(payload), magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> CFCheckptMessage:
        if len(payload) < 1 + 32 + 1:
            raise ValueError("cfcheckpt payload too short")
        filter_type = payload[0]
        stop_hash = bytes(payload[1:33])
        n, consumed = decode_varint(payload, 33)
        offset = 33 + consumed
        if offset + n * 32 > len(payload):
            raise ValueError("cfcheckpt payload truncated")
        headers = [bytes(payload[offset + 32 * i:offset + 32 * (i + 1)]) for i in range(n)]
        return cls(
            filter_type=filter_type,
            stop_hash=stop_hash,
            filter_headers=headers,
        )


# --- Additional P2P messages for chain-tip operation ---


@dataclass
class SendHeadersMessage:
    """
    ``sendheaders`` (BIP 130) — request that the peer announce new blocks
    via ``headers`` messages instead of ``inv``.  Empty payload.
    """

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="sendheaders", payload=b'', magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SendHeadersMessage:
        return cls()


@dataclass
class FeeFilterMessage:
    """
    ``feefilter`` (BIP 133) — tell the peer not to relay transactions
    below *feerate* (in sat/kB).
    """
    feerate: int = 1000  # satoshis per 1000 bytes

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<Q', self.feerate)
        return NetworkMessage(
            command="feefilter", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> FeeFilterMessage:
        if len(payload) < 8:
            raise ValueError("feefilter payload too short")
        feerate = struct.unpack('<Q', payload[:8])[0]
        return cls(feerate=feerate)


@dataclass
class WtxidRelayMessage:
    """
    ``wtxidrelay`` (BIP 339) — signal that the node wants to use witness
    txids for transaction relay.  Empty payload.  Sent before VERACK.
    """

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="wtxidrelay", payload=b'', magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> WtxidRelayMessage:
        return cls()


@dataclass
class SendAddrV2Message:
    """
    ``sendaddrv2`` (BIP 155) — signal that the node supports ADDRv2
    messages.  Empty payload.  Sent before VERACK.
    """

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="sendaddrv2", payload=b'', magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SendAddrV2Message:
        return cls()


@dataclass
class AddrV2Entry:
    """
    Single address entry in an addrv2 message (BIP155).

    Attributes:
        time: Unix timestamp when last seen
        services: Service flags (NODE_NETWORK, NODE_WITNESS, etc.)
        network_id: BIP155 network ID (1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS)
        addr: Raw address bytes (variable length based on network_id)
        port: Port number
    """
    time: int
    services: int
    network_id: int
    addr: bytes
    port: int

    def is_valid(self) -> bool:
        """Check if this address entry is valid per BIP155 rules."""
        # Check network ID is known
        if self.network_id not in BIP155_ADDR_SIZES:
            return False

        # TorV2 is deprecated and should be ignored
        if self.network_id == BIP155_NET_TORV2:
            return False

        # Check address length matches network ID
        expected_len = BIP155_ADDR_SIZES[self.network_id]
        if len(self.addr) != expected_len:
            return False

        # CJDNS addresses must start with 0xFC
        if self.network_id == BIP155_NET_CJDNS:
            if len(self.addr) < 1 or self.addr[0] != 0xFC:
                return False

        return True

    def to_string(self) -> str:
        """Convert address to human-readable string."""
        if self.network_id == BIP155_NET_IPV4:
            return f"{self.addr[0]}.{self.addr[1]}.{self.addr[2]}.{self.addr[3]}:{self.port}"
        elif self.network_id == BIP155_NET_IPV6:
            # Format as IPv6
            groups = [f"{self.addr[i]:02x}{self.addr[i+1]:02x}" for i in range(0, 16, 2)]
            return f"[{':'.join(groups)}]:{self.port}"
        elif self.network_id == BIP155_NET_TORV3:
            # TorV3: base32 encode with checksum
            import base64
            import hashlib
            # Compute checksum: SHA3-256(".onion checksum" || pubkey || version)[:2]
            checksum_prefix = b".onion checksum"
            version = bytes([3])
            h = hashlib.sha3_256(checksum_prefix + self.addr + version).digest()[:2]
            onion_bytes = self.addr + h + version
            # Base32 encode (lowercase, no padding)
            b32 = base64.b32encode(onion_bytes).decode('ascii').lower().rstrip('=')
            return f"{b32}.onion:{self.port}"
        elif self.network_id == BIP155_NET_I2P:
            # I2P: base32 encode (no padding)
            import base64
            b32 = base64.b32encode(self.addr).decode('ascii').lower().rstrip('=')
            return f"{b32}.b32.i2p:{self.port}"
        elif self.network_id == BIP155_NET_CJDNS:
            # CJDNS: IPv6 format
            groups = [f"{self.addr[i]:02x}{self.addr[i+1]:02x}" for i in range(0, 16, 2)]
            return f"[{':'.join(groups)}]:{self.port}"
        else:
            return f"unknown({self.network_id}):{self.port}"


@dataclass
class AddrV2Message:
    """
    ``addrv2`` (BIP 155) — extended address message supporting IPv6,
    Tor v3, I2P, and CJDNS addresses.

    Reference: Bitcoin Core protocol.h, netaddress.cpp

    Message format per entry:
    - time (4 bytes, uint32_t): last-seen timestamp
    - services (CompactSize): service flags
    - network_id (1 byte): BIP155 network type
    - addr_len (CompactSize): address byte length
    - addr (variable): raw address bytes
    - port (2 bytes, big-endian): port number
    """
    addresses: list[AddrV2Entry] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        """Serialize addrv2 message."""
        # Limit to MAX_ADDRV2_ADDRESSES
        addrs = self.addresses[:MAX_ADDRV2_ADDRESSES]

        data = encode_varint(len(addrs))
        for entry in addrs:
            data += struct.pack('<I', entry.time)
            data += encode_varint(entry.services)
            data += struct.pack('B', entry.network_id)
            data += encode_varint(len(entry.addr))
            data += entry.addr
            data += struct.pack('>H', entry.port)
        return NetworkMessage(
            command="addrv2", payload=data, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> AddrV2Message:
        """Deserialize addrv2 message from payload."""
        offset = 0
        count, consumed = decode_varint(payload, offset)
        offset += consumed

        # Enforce limit
        if count > MAX_ADDRV2_ADDRESSES:
            raise ValueError(f"addrv2 contains {count} addresses, max is {MAX_ADDRV2_ADDRESSES}")

        addresses = []
        for _ in range(count):
            # Time (4 bytes)
            if offset + 4 > len(payload):
                raise ValueError("addrv2 truncated: missing time field")
            ts = struct.unpack('<I', payload[offset:offset+4])[0]
            offset += 4

            # Services (CompactSize)
            services, consumed = decode_varint(payload, offset)
            offset += consumed

            # Network ID (1 byte)
            if offset >= len(payload):
                raise ValueError("addrv2 truncated: missing network_id")
            net_id = payload[offset]
            offset += 1

            # Address length (CompactSize)
            addr_len, consumed = decode_varint(payload, offset)
            offset += consumed

            # Validate address length
            if addr_len > MAX_ADDRV2_ADDR_SIZE:
                raise ValueError(f"addrv2 address too long: {addr_len} > {MAX_ADDRV2_ADDR_SIZE}")

            # Address bytes
            if offset + addr_len > len(payload):
                raise ValueError("addrv2 truncated: missing address bytes")
            addr_bytes = payload[offset:offset + addr_len]
            offset += addr_len

            # Port (2 bytes, big-endian)
            if offset + 2 > len(payload):
                raise ValueError("addrv2 truncated: missing port")
            port = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2

            entry = AddrV2Entry(
                time=ts,
                services=services,
                network_id=net_id,
                addr=addr_bytes,
                port=port,
            )

            # Validate entry per BIP155 rules
            # Skip invalid entries (unknown network, wrong length, deprecated TorV2)
            if entry.is_valid():
                addresses.append(entry)
            # else: silently drop invalid entries (Bitcoin Core behavior)

        return cls(addresses=addresses)

    @classmethod
    def from_dict_list(cls, addr_list: list[dict]) -> AddrV2Message:
        """Create AddrV2Message from a list of address dictionaries.

        For backwards compatibility with existing code that uses dict format.
        """
        entries = []
        for d in addr_list:
            entry = AddrV2Entry(
                time=d.get('time', int(time.time())),
                services=d.get('services', 0),
                network_id=d.get('network_id', BIP155_NET_IPV4),
                addr=d.get('addr', b'\x00' * 4),
                port=d.get('port', 8333),
            )
            if entry.is_valid():
                entries.append(entry)
        return cls(addresses=entries)


@dataclass
class NotFoundMessage:
    """
    ``notfound`` — sent in reply to ``getdata`` when the requested
    inventory items are not available.
    """
    inventory: list[tuple[int, bytes]]

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        inv_msg = InvMessage(self.inventory)
        payload = inv_msg.serialize_payload()
        return NetworkMessage(
            command="notfound", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> NotFoundMessage:
        inv = InvMessage.from_payload(payload)
        return cls(inventory=inv.inventory)


@dataclass
class MempoolMessage:
    """
    ``mempool`` (BIP 35) — request the peer's mempool contents as
    ``inv`` messages.  Empty payload.
    """

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="mempool", payload=b'', magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> MempoolMessage:
        return cls()


@dataclass
class AddrMessage:
    """``addr`` — list of known peer addresses."""
    addresses: list[tuple[int, NetworkAddress]] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        data = encode_varint(len(self.addresses))
        for ts, addr in self.addresses:
            data += struct.pack('<I', ts)
            data += addr.serialize()
        return NetworkMessage(
            command="addr", payload=data, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> AddrMessage:
        offset = 0
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        addresses = []
        for _ in range(count):
            ts = struct.unpack('<I', payload[offset:offset+4])[0]
            offset += 4
            addr, consumed = NetworkAddress.from_payload(payload, offset)
            offset += consumed
            addresses.append((ts, addr))
        return cls(addresses=addresses)


@dataclass
class GetAddrMessage:
    """``getaddr`` — request known peer addresses (empty payload)."""

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        return NetworkMessage(
            command="getaddr", payload=b"", magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetAddrMessage:
        return cls()


@dataclass
class GetBlocksMessage:
    """``getblocks`` — request block inventory."""
    version: int = 70015
    locator_hashes: list[bytes] = field(default_factory=list)
    hash_stop: bytes = b'\x00' * 32

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        data = struct.pack('<i', self.version)
        data += encode_varint(len(self.locator_hashes))
        for h in self.locator_hashes:
            data += h
        data += self.hash_stop
        return NetworkMessage(
            command="getblocks", payload=data, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetBlocksMessage:
        offset = 0
        version = struct.unpack('<i', payload[offset:offset+4])[0]
        offset += 4
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        # Anti-DoS: Bitcoin Core's MAX_LOCATOR_SZ = 101 (chain.h). Reject
        # before allocating to prevent an attacker from forcing arbitrary
        # memory allocation via a crafted getblocks message. Mirrors the
        # existing cap on GetHeadersMessage.from_payload above.
        if count > 101:
            raise ValueError(f"Too many locator hashes: {count}")
        hashes = []
        for _ in range(count):
            if offset + 32 > len(payload):
                raise ValueError("Not enough data for locator hash")
            hashes.append(payload[offset:offset+32])
            offset += 32
        if offset + 32 > len(payload):
            raise ValueError("Not enough data for hash_stop")
        hash_stop = payload[offset:offset+32]
        return cls(version=version, locator_hashes=hashes, hash_stop=hash_stop)


# BIP155 Network IDs (for addrv2 message)
# Reference: Bitcoin Core netaddress.h BIP155Network enum
BIP155_NET_IPV4 = 1     # IPv4 (4 bytes)
BIP155_NET_IPV6 = 2     # IPv6 (16 bytes)
BIP155_NET_TORV2 = 3    # TorV2 - DEPRECATED (10 bytes)
BIP155_NET_TORV3 = 4    # TorV3 (32 bytes, ed25519 pubkey)
BIP155_NET_I2P = 5      # I2P (32 bytes, destination hash)
BIP155_NET_CJDNS = 6    # CJDNS (16 bytes, starts with 0xFC)

# BIP155 address sizes per network ID
BIP155_ADDR_SIZES = {
    BIP155_NET_IPV4: 4,
    BIP155_NET_IPV6: 16,
    BIP155_NET_TORV2: 10,  # deprecated but still need to parse
    BIP155_NET_TORV3: 32,
    BIP155_NET_I2P: 32,
    BIP155_NET_CJDNS: 16,
}

# Maximum addresses per addrv2 message
MAX_ADDRV2_ADDRESSES = 1000

# Maximum address size per BIP155
MAX_ADDRV2_ADDR_SIZE = 512


# BIP 330 Erlay Transaction Reconciliation messages


@dataclass
class SendTxRcnclMessage:
    """
    ``sendtxrcncl`` (BIP 330) — negotiate transaction reconciliation.

    Sent during the version handshake (after VERACK, before any INV/TX
    messages).  Both peers must send ``sendtxrcncl`` for Erlay to be
    active on the connection.

    Fields:
        version: reconciliation protocol version (currently 1)
        salt: 64-bit random salt used to compute short txid mappings
              for set reconciliation.  Each side provides its own salt;
              the actual sketch salt is derived from both.
    """
    version: int = 1
    salt: int = 0

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<I', self.version)
        payload += struct.pack('<Q', self.salt)
        return NetworkMessage(
            command="sendtxrcncl", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SendTxRcnclMessage:
        if len(payload) < 12:
            raise ValueError("sendtxrcncl payload too short")
        version = struct.unpack('<I', payload[:4])[0]
        salt = struct.unpack('<Q', payload[4:12])[0]
        return cls(version=version, salt=salt)


@dataclass
class ReqTxRcnclMessage:
    """
    ``reqtxrcncl`` (BIP 330) — request reconciliation with a peer.

    Sent by the reconciliation initiator to begin a sketch-based
    set reconciliation round.

    Fields:
        set_size: number of transactions in the sender's local
                  reconciliation set for this peer (helps receiver
                  choose an appropriate sketch capacity).
        q: a fixed-point fraction (uint16, Q=q/2^15) encoding the
           estimated ratio of the symmetric difference to set_size.
           This guides sketch capacity selection.
    """
    set_size: int = 0
    q: int = 1  # Q coefficient — fraction * 2^15

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<I', self.set_size)
        payload += struct.pack('<H', self.q)
        return NetworkMessage(
            command="reqtxrcncl", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> ReqTxRcnclMessage:
        if len(payload) < 6:
            raise ValueError("reqtxrcncl payload too short")
        set_size = struct.unpack('<I', payload[:4])[0]
        q = struct.unpack('<H', payload[4:6])[0]
        return cls(set_size=set_size, q=q)


@dataclass
class SketchMessage:
    """
    ``sketch`` (BIP 330) — carry a minisketch-encoded sketch.

    Sent by the reconciliation responder in reply to ``reqtxrcncl``.
    The sketch encodes the responder's reconciliation set so that
    the initiator can compute the symmetric difference.

    Fields:
        sketch_data: raw minisketch bytes (variable length, depends
                     on the agreed capacity).
    """
    sketch_data: bytes = b''

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = encode_varint(len(self.sketch_data))
        payload += self.sketch_data
        return NetworkMessage(
            command="sketch", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SketchMessage:
        offset = 0
        length, consumed = decode_varint(payload, offset)
        offset += consumed
        if len(payload) < offset + length:
            raise ValueError("sketch payload too short")
        sketch_data = payload[offset:offset + length]
        return cls(sketch_data=sketch_data)


@dataclass
class ReconcilDiffMessage:
    """
    ``reconcildiff`` (BIP 330) — exchange set differences after
    reconciliation.

    Sent by the initiator after decoding the sketch difference.
    Contains the list of short txids that the initiator has but
    the responder is missing, and requests the txids the responder
    has that the initiator is missing.

    Fields:
        success: whether sketch decoding succeeded
        ask_shortids: short txids the sender wants (responder has, sender lacks)
    """
    success: bool = True
    ask_shortids: list[int] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<B', 1 if self.success else 0)
        payload += encode_varint(len(self.ask_shortids))
        for sid in self.ask_shortids:
            payload += struct.pack('<I', sid)
        return NetworkMessage(
            command="reconcildiff", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> ReconcilDiffMessage:
        if len(payload) < 1:
            raise ValueError("reconcildiff payload too short")
        offset = 0
        success = bool(payload[offset])
        offset += 1
        count, consumed = decode_varint(payload, offset)
        offset += consumed
        ask_shortids = []
        for _ in range(count):
            if offset + 4 > len(payload):
                raise ValueError("reconcildiff payload truncated")
            sid = struct.unpack('<I', payload[offset:offset + 4])[0]
            ask_shortids.append(sid)
            offset += 4
        return cls(success=success, ask_shortids=ask_shortids)


# BIP 331 Package Relay messages (draft)
# https://github.com/bitcoin/bips/blob/master/bip-0331.mediawiki

# Package relay inventory type
MSG_PKGTXNS = 6  # Package transactions


@dataclass
class SendPackagesMessage:
    """
    ``sendpackages`` (BIP 331) — negotiate package relay support.

    Sent after the version handshake.  If both peers send this message,
    package relay is enabled for the connection.

    Fields:
        version: package relay protocol version (currently 1)
        max_count: maximum number of transactions in a package this peer accepts
        max_weight: maximum total weight of a package this peer accepts
    """
    version: int = 1
    max_count: int = 25
    max_weight: int = 404_000

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = struct.pack('<I', self.version)
        payload += struct.pack('<I', self.max_count)
        payload += struct.pack('<I', self.max_weight)
        return NetworkMessage(
            command="sendpackages", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> SendPackagesMessage:
        if len(payload) < 12:
            raise ValueError("sendpackages payload too short")
        version = struct.unpack('<I', payload[:4])[0]
        max_count = struct.unpack('<I', payload[4:8])[0]
        max_weight = struct.unpack('<I', payload[8:12])[0]
        return cls(version=version, max_count=max_count, max_weight=max_weight)


@dataclass
class GetPkgTxnsMessage:
    """
    ``getpkgtxns`` (BIP 331) — request a package by announcing the child's wtxid.

    When a peer announces a transaction via inv with type MSG_PKGTXNS,
    the receiving peer sends this message to request the package.

    Fields:
        child_wtxid: witness transaction ID of the child transaction
    """
    child_wtxid: bytes

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        if len(self.child_wtxid) != 32:
            raise ValueError(f"Invalid wtxid length: {len(self.child_wtxid)}")
        return NetworkMessage(
            command="getpkgtxns", payload=self.child_wtxid, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> GetPkgTxnsMessage:
        if len(payload) != 32:
            raise ValueError(f"getpkgtxns payload must be 32 bytes, got {len(payload)}")
        return cls(child_wtxid=payload)


@dataclass
class PkgTxnsMessage:
    """
    ``pkgtxns`` (BIP 331) — deliver a package of transactions.

    Sent in response to getpkgtxns.  Contains the full package in
    topological order (parents first, child last).

    Fields:
        transactions: list of serialized transactions (as raw bytes)
    """
    transactions: list[bytes] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        payload = encode_varint(len(self.transactions))
        for tx_bytes in self.transactions:
            payload += encode_varint(len(tx_bytes))
            payload += tx_bytes
        return NetworkMessage(
            command="pkgtxns", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> PkgTxnsMessage:
        offset = 0
        tx_count, consumed = decode_varint(payload, offset)
        offset += consumed

        if tx_count > 25:
            raise ValueError(f"pkgtxns contains too many transactions: {tx_count}")

        transactions = []
        for _ in range(tx_count):
            tx_len, consumed = decode_varint(payload, offset)
            offset += consumed
            if offset + tx_len > len(payload):
                raise ValueError("pkgtxns payload truncated")
            tx_bytes = payload[offset:offset + tx_len]
            offset += tx_len
            transactions.append(tx_bytes)

        return cls(transactions=transactions)


@dataclass
class AncPkgInfoMessage:
    """
    ``ancpkginfo`` (BIP 331) — announce package info for ancestor package relay.

    When a peer receives a transaction that is in the orphan pool and the
    parent is in reconsiderable rejects (low fee), they can request the
    ancestor package info to understand the full package fee rate.

    Fields:
        child_wtxid: witness txid of the child transaction
        parent_wtxids: list of witness txids of parent transactions
    """
    child_wtxid: bytes
    parent_wtxids: list[bytes] = field(default_factory=list)

    def to_network_message(self, network: str = "mainnet") -> NetworkMessage:
        if len(self.child_wtxid) != 32:
            raise ValueError(f"Invalid child wtxid length: {len(self.child_wtxid)}")
        payload = self.child_wtxid
        payload += encode_varint(len(self.parent_wtxids))
        for parent_wtxid in self.parent_wtxids:
            if len(parent_wtxid) != 32:
                raise ValueError(f"Invalid parent wtxid length: {len(parent_wtxid)}")
            payload += parent_wtxid
        return NetworkMessage(
            command="ancpkginfo", payload=payload, magic=get_magic(network))

    @classmethod
    def from_payload(cls, payload: bytes) -> AncPkgInfoMessage:
        if len(payload) < 33:
            raise ValueError("ancpkginfo payload too short")
        offset = 0
        child_wtxid = payload[offset:offset + 32]
        offset += 32

        parent_count, consumed = decode_varint(payload, offset)
        offset += consumed

        if parent_count > 24:  # max 24 parents + 1 child = 25 package limit
            raise ValueError(f"ancpkginfo contains too many parents: {parent_count}")

        parent_wtxids = []
        for _ in range(parent_count):
            if offset + 32 > len(payload):
                raise ValueError("ancpkginfo payload truncated")
            parent_wtxids.append(payload[offset:offset + 32])
            offset += 32

        return cls(child_wtxid=child_wtxid, parent_wtxids=parent_wtxids)
