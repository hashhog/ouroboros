"""
Bitcoin peer connection management.

This module implements peer-to-peer connection management with asyncio,
including connection, handshake, message handling, and error recovery.
Supports SOCKS5 proxy connections for Tor (.onion) and general proxying.
"""

import asyncio
import struct
import hashlib
import time
import random
import logging
from typing import Optional, Callable, Dict, Tuple
from enum import Enum

from ouroboros.p2p_messages import (
    NetworkMessage,
    VersionMessage,
    PingMessage,
    PongMessage,
    NetworkAddress,
    get_magic,
    MAGIC_MAINNET,
    MAGIC_TESTNET,
    MAGIC_REGTEST,
    NODE_NETWORK,
    NODE_WITNESS,
    NODE_P2P_V2,
)
from ouroboros.transport_v2 import V2Handshake, V2Transport

logger = logging.getLogger(__name__)


# SOCKS5 constants (RFC 1928)

SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCESS = 0x00


def is_onion_host(host: str) -> bool:
    """Return True if *host* is a Tor v3 .onion address."""
    return host.lower().endswith(".onion")


def parse_proxy_addr(proxy_str: str) -> Tuple[str, int]:
    """Parse a ``host:port`` proxy string and return ``(host, port)``; raises ValueError if invalid."""
    if not proxy_str:
        raise ValueError("empty proxy string")
    # Handle IPv6 bracket notation [::1]:9050
    if proxy_str.startswith("["):
        bracket_end = proxy_str.index("]")
        host = proxy_str[1:bracket_end]
        port_str = proxy_str[bracket_end + 2:]  # skip ']:'
    else:
        parts = proxy_str.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid proxy address: {proxy_str}")
        host, port_str = parts
    return host, int(port_str)


async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Establish a TCP connection through a SOCKS5 proxy (RFC 1928, no-auth, CONNECT).

    Sends *dest_host* as a domain name so the proxy (Tor) resolves .onion addresses.
    Returns ``(reader, writer)`` connected to *dest_host:dest_port* via the proxy.
    """
    # 1. TCP connect to the proxy
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        # 2. SOCKS5 greeting: version + 1 auth method (no-auth)
        writer.write(struct.pack("BBB", SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE))
        await writer.drain()

        # 3. Read server's chosen auth method
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected version {resp[0]}")
        if resp[1] != SOCKS5_AUTH_NONE:
            raise Exception(f"SOCKS5: server rejected no-auth (method={resp[1]:#x})")

        # 4. CONNECT request
        # Use domain name addressing so Tor can resolve .onion addresses
        host_bytes = dest_host.encode("ascii")
        connect_req = struct.pack(
            "!BBBB",
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,  # reserved
            SOCKS5_ATYP_DOMAINNAME,
        )
        connect_req += struct.pack("B", len(host_bytes)) + host_bytes
        connect_req += struct.pack("!H", dest_port)
        writer.write(connect_req)
        await writer.drain()

        # 5. Read CONNECT reply (minimum 10 bytes for IPv4 bind addr)
        reply_header = await asyncio.wait_for(
            reader.readexactly(4), timeout=timeout
        )
        if reply_header[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected reply version {reply_header[0]}")
        if reply_header[1] != SOCKS5_REPLY_SUCCESS:
            raise Exception(
                f"SOCKS5: CONNECT failed with status {reply_header[1]:#x}"
            )

        # Consume the bind address (we don't need it but must drain it)
        atyp = reply_header[3]
        if atyp == SOCKS5_ATYP_IPV4:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_IPV6:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            domain_len_bytes = await asyncio.wait_for(
                reader.readexactly(1), timeout=timeout
            )
            await asyncio.wait_for(
                reader.readexactly(domain_len_bytes[0] + 2), timeout=timeout
            )
        else:
            raise Exception(f"SOCKS5: unknown bind address type {atyp:#x}")

        logger.debug(
            f"SOCKS5 tunnel established to {dest_host}:{dest_port} "
            f"via {proxy_host}:{proxy_port}"
        )
        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


class PeerState(Enum):
    """Peer connection state"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    HANDSHAKING = 3
    READY = 4


# Minimum protocol version for segwit support (BIP 144)
MIN_PEER_VERSION = 70015

# Handshake timeout in seconds
HANDSHAKE_TIMEOUT = 60.0


class RelayType(Enum):
    """Peer relay type — determines what messages we exchange."""
    FULL_RELAY = "full_relay"
    BLOCK_RELAY_ONLY = "block_relay_only"


class Peer:
    """Manages connection to a single Bitcoin peer"""
    
    def __init__(
        self,
        host: str,
        port: int,
        network: str = "mainnet",
        transport_version: int = 1,
        inbound: bool = False,
        relay_txs: bool = True,
        proxy: Optional[str] = None,
    ):
        """Initialize peer connection."""
        self.host = host
        self.port = port
        self.network = network
        self.transport_version = transport_version
        self.inbound = inbound
        self.relay_txs = relay_txs
        self.proxy = proxy  # SOCKS5 proxy "host:port" or None
        self.relay_type = (
            RelayType.FULL_RELAY if relay_txs else RelayType.BLOCK_RELAY_ONLY
        )
        self.state = PeerState.DISCONNECTED
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        
        # BIP 324 v2 transport (set after successful negotiation)
        self._v2_transport: Optional[V2Transport] = None
        self._v2_recv_buffer: bytes = b""
        
        self.version: Optional[int] = None
        self.services: int = 0
        self.user_agent: str = ""
        self.start_height: int = 0
        
        self.last_ping: float = 0
        self.latency: float = 0
        self.score: int = 100  # Reputation score (0-100)
        
        self.message_handlers: Dict[str, Callable] = {}
        self._listen_task: Optional[asyncio.Task] = None
        self._ping_task: Optional[asyncio.Task] = None
        
        # Peer announcement preferences (set by sendheaders / sendcmpct)
        self.wants_headers: bool = False      # BIP 130: prefer headers announcements
        self.wants_cmpctblock: bool = False    # BIP 152: announce via cmpctblock

        # BIP 133: peer's minimum fee rate for tx relay (sat/kB)
        self.peer_feefilter: int = 0

        # BIP 330: Erlay reconciliation support
        self.erlay_enabled: bool = False       # Set to True when sendtxrcncl exchanged

        # Timestamps used by the inbound eviction algorithm
        self.connected_at: float = time.time()
        self.last_block_time: float = 0.0  # last useful block relay activity

        # Connection retry settings
        self._retry_count = 0
        self._max_retries = 3
        self._retry_delay = 5.0  # seconds

        # Handshake state tracking (Phase 16)
        # The handshake is complete only after both VERSION and VERACK are exchanged
        self.handshake_complete: bool = False
        self._version_received: bool = False
        self._verack_received: bool = False
        self._version_sent: bool = False
        self._verack_sent: bool = False

        # BIP 339: peer supports wtxid relay
        self.wtxid_relay: bool = False
        # BIP 155: peer supports addrv2
        self.addrv2: bool = False
    
    async def connect(self, start_height: int = 0, retry: bool = True) -> bool:
        """Connect to the peer, complete the version handshake, and start background tasks."""
        max_attempts = self._max_retries + 1 if retry else 1
        
        for attempt in range(max_attempts):
            try:
                logger.info(f"Connecting to {self.host}:{self.port} (attempt {attempt + 1}/{max_attempts})")
                self.state = PeerState.CONNECTING

                # Establish TCP connection with timeout
                # Use SOCKS5 proxy for .onion addresses or when proxy is
                # configured for all outbound connections.
                use_proxy = self.proxy and (
                    is_onion_host(self.host) or self.proxy
                )
                if use_proxy:
                    proxy_host, proxy_port = parse_proxy_addr(self.proxy)
                    logger.info(
                        f"Connecting via SOCKS5 proxy {proxy_host}:{proxy_port} "
                        f"to {self.host}:{self.port}"
                    )
                    self.reader, self.writer = await socks5_connect(
                        proxy_host, proxy_port,
                        self.host, self.port,
                        timeout=10.0,
                    )
                else:
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port),
                        timeout=10.0
                    )
                
                self.state = PeerState.CONNECTED

                # BIP 324 v2 transport negotiation (before version handshake)
                if self.transport_version == 2:
                    try:
                        await self._negotiate_v2()
                    except Exception as v2_err:
                        logger.warning(
                            f"v2 transport negotiation failed with "
                            f"{self.host}:{self.port}, falling back to v1: {v2_err}"
                        )
                        self._v2_transport = None

                # Perform handshake
                await self._handshake(start_height)
                
                self.state = PeerState.READY
                self._retry_count = 0
                
                logger.info(
                    f"Connected to {self.host}:{self.port} - "
                    f"{self.user_agent} (version {self.version})"
                )
                
                # Start listening for messages
                self._listen_task = asyncio.create_task(self.listen())
                
                # Start periodic ping
                self._ping_task = asyncio.create_task(self._ping_loop())
                
                return True
                
            except asyncio.TimeoutError:
                logger.warning(
                    f"Connection timeout to {self.host}:{self.port} "
                    f"(attempt {attempt + 1}/{max_attempts})"
                )
                await self.disconnect()
                if attempt < max_attempts - 1:
                    await asyncio.sleep(self._retry_delay)
                    
            except Exception as e:
                logger.error(
                    f"Failed to connect to {self.host}:{self.port} "
                    f"(attempt {attempt + 1}/{max_attempts}): {e}"
                )
                await self.disconnect()
                if attempt < max_attempts - 1:
                    await asyncio.sleep(self._retry_delay)
        
        logger.error(f"Failed to connect to {self.host}:{self.port} after {max_attempts} attempts")
        return False
    
    async def accept_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        start_height: int = 0,
    ) -> bool:
        """Accept an already-established inbound connection and complete the reversed handshake.

        Waits for the peer's version first, then sends ours — the opposite of outbound order.
        """
        try:
            self.reader = reader
            self.writer = writer
            self.state = PeerState.CONNECTED

            # Inbound handshake: receive version first, then send ours
            await self._inbound_handshake(start_height)

            self.state = PeerState.READY

            logger.info(
                f"Accepted inbound peer {self.host}:{self.port} - "
                f"{self.user_agent} (version {self.version})"
            )

            # Start background tasks
            self._listen_task = asyncio.create_task(self.listen())
            self._ping_task = asyncio.create_task(self._ping_loop())

            return True
        except Exception as e:
            logger.warning(
                f"Inbound handshake failed from {self.host}:{self.port}: {e}"
            )
            await self.disconnect()
            return False

    async def _inbound_handshake(self, start_height: int):
        """Perform version handshake as the responder (inbound).

        Message sequence (matching Bitcoin Core net_processing.cpp):
        1. Receive VERSION from peer
        2. Validate peer version (must be >= MIN_PEER_VERSION for segwit)
        3. Send our VERSION
        4. Send WTXIDRELAY (BIP 339) if version >= 70016
        5. Send SENDADDRV2 (BIP 155) if version >= 70016
        6. Send VERACK
        7. Receive VERACK -> handshake complete
        """
        self.state = PeerState.HANDSHAKING

        from ouroboros.p2p_messages import (
            SendHeadersMessage, SendCmpctMessage,
            FeeFilterMessage, WtxidRelayMessage, SendAddrV2Message,
        )

        # 1. Receive version from remote peer with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")

        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        self._version_received = True

        # Reject peers with version < MIN_PEER_VERSION (no segwit support)
        if self.version < MIN_PEER_VERSION:
            raise Exception(
                f"Inbound peer {self.host}:{self.port} version {self.version} < {MIN_PEER_VERSION} "
                "(segwit required)"
            )

        # Validate peer service flags
        if not (self.services & NODE_NETWORK):
            logger.warning(
                f"Inbound peer {self.host}:{self.port} lacks NODE_NETWORK — "
                "may not serve full blocks"
            )
        if not (self.services & NODE_WITNESS):
            logger.warning(
                f"Inbound peer {self.host}:{self.port} lacks NODE_WITNESS — "
                "will not relay witness data"
            )

        # 2. Send our version
        addr_recv = self._create_network_address(self.host, self.port)
        addr_from = self._create_network_address("0.0.0.0", 8333)

        our_services = NODE_NETWORK | NODE_WITNESS
        if self.transport_version >= 2:
            our_services |= NODE_P2P_V2
        version_msg = VersionMessage(
            version=70016,
            services=our_services,
            timestamp=int(time.time()),
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=self._generate_nonce(),
            user_agent='/ouroboros:0.1.0/',
            start_height=start_height,
            relay=self.relay_txs,
        )
        await self.send_message(version_msg.to_network_message(self.network))
        self._version_sent = True

        # Calculate greatest common version for feature negotiation
        greatest_common_version = min(70016, self.version)

        # 3. BIP 339: Send WTXIDRELAY before VERACK if version >= 70016
        if greatest_common_version >= 70016 and self.relay_txs:
            try:
                await self.send_message(
                    WtxidRelayMessage().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send wtxidrelay: {e}")

        # 4. BIP 155: Send SENDADDRV2 before VERACK if version >= 70016
        if greatest_common_version >= 70016:
            try:
                await self.send_message(
                    SendAddrV2Message().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send sendaddrv2: {e}")

        # 5. Send verack
        verack = NetworkMessage(
            command="verack", payload=b"", magic=get_magic(self.network)
        )
        await self.send_message(verack)
        self._verack_sent = True

        # 6. Receive verack with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "verack":
            raise Exception(f"Expected verack, got {msg.command}")
        self._verack_received = True

        # Handshake is now complete
        self.handshake_complete = True

        # Post-handshake feature negotiation (sent AFTER verack exchange)
        try:
            await self.send_message(
                SendHeadersMessage().to_network_message(self.network))
            if self.relay_txs:
                await self.send_message(
                    SendCmpctMessage(announce=False, version=2).to_network_message(self.network))
                await self.send_message(
                    FeeFilterMessage(feerate=1000).to_network_message(self.network))
            else:
                logger.debug(
                    f"Block-relay-only inbound peer {self.host}:{self.port} — "
                    "skipping sendcmpct/feefilter"
                )
        except Exception as feat_err:
            logger.debug(f"Feature negotiation error (non-fatal): {feat_err}")

    async def _negotiate_v2(self) -> None:
        if not self.reader or not self.writer:
            raise Exception("Not connected")

        handshake = V2Handshake(initiator=True)

        # Send our 64-byte ElligatorSwift public key
        self.writer.write(handshake.local_pubkey_bytes)
        await self.writer.drain()

        # Read the peer's 64-byte ElligatorSwift public key
        remote_pubkey = await asyncio.wait_for(
            self.reader.readexactly(64),
            timeout=10.0,
        )

        handshake.receive_remote_pubkey(remote_pubkey)
        self._v2_transport = V2Transport.from_handshake(handshake)
        logger.info(
            f"BIP 324 v2 transport established with {self.host}:{self.port}"
        )

    async def _handshake(self, start_height: int):
        """Perform version handshake (outbound connection).

        Message sequence (matching Bitcoin Core net_processing.cpp):
        1. Send VERSION
        2. Receive VERSION
        3. Validate peer version (must be >= MIN_PEER_VERSION for segwit)
        4. Send WTXIDRELAY (BIP 339) if version >= 70016
        5. Send SENDADDRV2 (BIP 155) if version >= 70016
        6. Send VERACK
        7. Receive VERACK -> handshake complete
        """
        self.state = PeerState.HANDSHAKING

        from ouroboros.p2p_messages import (
            SendHeadersMessage, SendCmpctMessage,
            FeeFilterMessage, WtxidRelayMessage, SendAddrV2Message,
        )

        # Create network addresses
        addr_recv = self._create_network_address(self.host, self.port)
        addr_from = self._create_network_address("0.0.0.0", 8333)

        # Send version message
        # Block-relay-only connections set relay=False (BIP 37) to signal
        # that we do not want transaction relay on this connection.
        our_services = NODE_NETWORK | NODE_WITNESS
        if self.transport_version >= 2:
            our_services |= NODE_P2P_V2
        version_msg = VersionMessage(
            version=70016,
            services=our_services,
            timestamp=int(time.time()),
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=self._generate_nonce(),
            user_agent="/ouroboros:0.1.0/",
            start_height=start_height,
            relay=self.relay_txs,
        )

        await self.send_message(version_msg.to_network_message(self.network))
        self._version_sent = True

        # Receive version message with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")

        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        self._version_received = True

        # Reject peers with version < MIN_PEER_VERSION (no segwit support)
        if self.version < MIN_PEER_VERSION:
            raise Exception(
                f"Peer {self.host}:{self.port} version {self.version} < {MIN_PEER_VERSION} "
                "(segwit required)"
            )

        # Validate peer service flags
        if not (self.services & NODE_NETWORK):
            logger.warning(
                f"Peer {self.host}:{self.port} lacks NODE_NETWORK — "
                "may not serve full blocks"
            )
        if not (self.services & NODE_WITNESS):
            logger.warning(
                f"Peer {self.host}:{self.port} lacks NODE_WITNESS — "
                "will not relay witness data"
            )

        # Calculate greatest common version for feature negotiation
        greatest_common_version = min(70016, self.version)

        # BIP 339: Send WTXIDRELAY before VERACK if version >= 70016
        # (must be sent during handshake, not after)
        if greatest_common_version >= 70016 and self.relay_txs:
            try:
                await self.send_message(
                    WtxidRelayMessage().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send wtxidrelay: {e}")

        # BIP 155: Send SENDADDRV2 before VERACK if version >= 70016
        if greatest_common_version >= 70016:
            try:
                await self.send_message(
                    SendAddrV2Message().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send sendaddrv2: {e}")

        # Send verack
        verack = NetworkMessage(command="verack", payload=b"", magic=get_magic(self.network))
        await self.send_message(verack)
        self._verack_sent = True

        # Receive verack with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "verack":
            raise Exception(f"Expected verack, got {msg.command}")
        self._verack_received = True

        # Handshake is now complete
        self.handshake_complete = True

        # Post-handshake feature negotiation messages
        # These are sent AFTER verack exchange
        try:
            # sendheaders is always sent — we want header announcements
            # even on block-relay-only connections
            await self.send_message(
                SendHeadersMessage().to_network_message(self.network))

            if self.relay_txs:
                # Full-relay peers get the complete feature set
                await self.send_message(
                    SendCmpctMessage(announce=False, version=2).to_network_message(self.network))
                await self.send_message(
                    FeeFilterMessage(feerate=1000).to_network_message(self.network))
            else:
                logger.debug(
                    f"Block-relay-only peer {self.host}:{self.port} — "
                    "skipping sendcmpct/feefilter"
                )
        except Exception as feat_err:
            logger.debug(f"Feature negotiation error (non-fatal): {feat_err}")
    
    def _create_network_address(self, host: str, port: int) -> NetworkAddress:
        """Create network address from host and port."""
        our_services = NODE_NETWORK | NODE_WITNESS

        # .onion addresses — use all-zeros IP (the real routing happens
        # via the SOCKS5 proxy; the version message just needs a valid
        # NetworkAddress structure).
        if is_onion_host(host):
            return NetworkAddress(services=our_services, ip=b'\x00' * 16, port=port)

        # Try to parse as IPv4
        try:
            parts = host.split('.')
            if len(parts) == 4:
                # Validate all parts are integers
                for p in parts:
                    int(p)
                return NetworkAddress.from_ipv4(host, port, services=our_services)
        except (ValueError, AttributeError):
            pass

        # TODO: handle IPv6
        # Default to all zeros (unknown address)
        return NetworkAddress(services=our_services, ip=b'\x00' * 16, port=port)
    
    async def send_message(self, msg: NetworkMessage):
        """Serialize and write *msg* to the peer (encrypted if BIP 324 v2 is active)."""
        if self.state != PeerState.READY and self.state != PeerState.HANDSHAKING:
            raise Exception(f"Cannot send message in state {self.state}")
        
        if not self.writer:
            raise Exception("Not connected")
        
        data = msg.serialize()

        if self._v2_transport is not None:
            data = self._v2_transport.encrypt_message(data)

        self.writer.write(data)
        await self.writer.drain()
        
        logger.debug(f"Sent {msg.command} to {self.host}:{self.port}")
    
    async def receive_message(self, timeout: float = 30.0) -> NetworkMessage:
        """Read and parse the next message from the peer (v1 or BIP 324 v2); raises on timeout or bad format."""
        if not self.reader:
            raise Exception("Not connected")

        # v2 encrypted path
        if self._v2_transport is not None:
            return await self._receive_v2_message(timeout)

        # v1 plaintext path
        # Read header (24 bytes)
        header = await asyncio.wait_for(
            self.reader.readexactly(24),
            timeout=timeout
        )
        
        # Parse header
        magic, command_bytes, length, checksum = struct.unpack('<I12sI4s', header)
        command = command_bytes.rstrip(b'\x00').decode('ascii')
        
        # Verify magic bytes
        expected_magic = get_magic(self.network)
        if magic != expected_magic:
            raise Exception(
                f"Invalid magic bytes: expected {expected_magic:08x}, got {magic:08x}"
            )
        
        # Read payload
        payload = b''
        if length > 0:
            if length > 32 * 1024 * 1024:  # 32 MB limit
                raise Exception(f"Payload too large: {length} bytes")
            
            payload = await asyncio.wait_for(
                self.reader.readexactly(length),
                timeout=timeout
            )
        
        # Verify checksum
        expected_checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]
        
        if checksum != expected_checksum:
            raise Exception(f"Checksum mismatch for {command}")
        
        logger.debug(f"Received {command} from {self.host}:{self.port} ({len(payload)} bytes)")
        
        return NetworkMessage(command=command, payload=payload, magic=magic)

    async def _receive_v2_message(self, timeout: float) -> NetworkMessage:
        """Receive and decrypt a BIP 324 v2 message."""
        while True:
            # Read the encrypted length field (3 bytes + 16-byte Poly1305 tag)
            enc_length = await asyncio.wait_for(
                self.reader.readexactly(3 + 16),
                timeout=timeout,
            )

            length_plain = self._v2_transport.recv_cipher.decrypt(enc_length)
            msg_len = int.from_bytes(length_plain, "little")

            if msg_len > 32 * 1024 * 1024:
                raise Exception(f"v2 payload too large: {msg_len} bytes")

            # Read the encrypted payload (msg_len + 16-byte tag)
            enc_payload = await asyncio.wait_for(
                self.reader.readexactly(msg_len + 16),
                timeout=timeout,
            )

            inner = self._v2_transport.recv_cipher.decrypt(enc_payload)
            from ouroboros.transport_v2 import PacketType
            is_decoy = inner[0] == PacketType.DECOY
            payload = inner[1:]

            if is_decoy:
                logger.debug(f"Discarded decoy packet from {self.host}:{self.port}")
                continue

            # The payload is the original v1 serialised NetworkMessage
            return NetworkMessage.deserialize(payload, network=self.network)
    
    def _is_handshake_message(self, command: str) -> bool:
        """Check if message is allowed during handshake (before handshake_complete)."""
        # Bitcoin Core net_processing.cpp: only version/verack/wtxidrelay/sendaddrv2
        # are allowed before handshake completes
        return command in ("version", "verack", "wtxidrelay", "sendaddrv2")

    async def listen(self):
        """Message receive loop: dispatches to registered handlers until disconnected.

        Pre-handshake filtering: If handshake_complete is False, only accept
        VERSION, VERACK, WTXIDRELAY, and SENDADDRV2 messages. All other messages
        are dropped/ignored per Bitcoin Core's net_processing.cpp behavior.
        """
        try:
            while self.state == PeerState.READY:
                try:
                    msg = await self.receive_message(timeout=60.0)

                    # Pre-handshake message filtering (Phase 16)
                    # Should not normally happen since listen() starts after
                    # handshake, but included for safety and protocol correctness
                    if not self.handshake_complete:
                        if not self._is_handshake_message(msg.command):
                            logger.warning(
                                f"Dropping non-handshake message '{msg.command}' "
                                f"before handshake complete from {self.host}:{self.port}"
                            )
                            self.adjust_score(-10)
                            continue

                    # Handle feature negotiation messages (BIP 339, BIP 155)
                    # These can arrive after VERACK but we still track them
                    if msg.command == "wtxidrelay":
                        if self.handshake_complete:
                            # Per BIP 339, wtxidrelay must be sent before VERACK
                            # If received after, Bitcoin Core disconnects
                            logger.warning(
                                f"wtxidrelay received after verack from "
                                f"{self.host}:{self.port}, ignoring"
                            )
                        else:
                            self.wtxid_relay = True
                            logger.debug(f"Peer {self.host}:{self.port} supports wtxid relay")
                        continue

                    if msg.command == "sendaddrv2":
                        if self.handshake_complete:
                            # Per BIP 155, sendaddrv2 must be sent before VERACK
                            logger.warning(
                                f"sendaddrv2 received after verack from "
                                f"{self.host}:{self.port}, ignoring"
                            )
                        else:
                            self.addrv2 = True
                            logger.debug(f"Peer {self.host}:{self.port} supports addrv2")
                        continue

                    # Handle ping/pong automatically
                    if msg.command == "ping":
                        ping = PingMessage.from_payload(msg.payload)
                        pong = PongMessage(nonce=ping.nonce)
                        pong_msg = pong.to_network_message(self.network)
                        await self.send_message(pong_msg)
                        continue

                    if msg.command == "pong":
                        pong = PongMessage.from_payload(msg.payload)
                        if self.last_ping > 0:
                            self.latency = time.time() - self.last_ping
                            logger.debug(
                                f"Pong from {self.host}:{self.port} - "
                                f"latency: {self.latency:.3f}s"
                            )
                        continue

                    # Dispatch to handler
                    if msg.command in self.message_handlers:
                        try:
                            await self.message_handlers[msg.command](msg)
                        except Exception as e:
                            logger.error(
                                f"Error in handler for {msg.command} "
                                f"from {self.host}:{self.port}: {e}"
                            )
                    else:
                        logger.debug(
                            f"No handler for {msg.command} from {self.host}:{self.port}"
                        )

                except asyncio.TimeoutError:
                    # Timeout is normal, just continue listening
                    logger.debug(f"Receive timeout from {self.host}:{self.port}")
                    continue

                except Exception as e:
                    logger.error(
                        f"Error receiving message from {self.host}:{self.port}: {e}"
                    )
                    # Don't disconnect on single message error, but adjust score
                    self.adjust_score(-5)
                    if self.score <= 0:
                        await self.disconnect()
                        break

        except asyncio.CancelledError:
            logger.info(f"Peer {self.host}:{self.port} listener cancelled")
        except Exception as e:
            logger.error(f"Error in peer {self.host}:{self.port} listener: {e}")
            await self.disconnect()
    
    async def _ping_loop(self):
        try:
            while self.state == PeerState.READY:
                await asyncio.sleep(120.0)  # Ping every 2 minutes
                if self.state == PeerState.READY:
                    await self.ping()
        except asyncio.CancelledError:
            logger.debug(f"Ping loop cancelled for {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Error in ping loop for {self.host}:{self.port}: {e}")
    
    def register_handler(self, command: str, handler: Callable):
        """Register *handler* to be called when a message with *command* is received."""
        self.message_handlers[command] = handler
        logger.debug(f"Registered handler for {command} on {self.host}:{self.port}")
    
    async def ping(self):
        """Send ping to peer"""
        nonce = self._generate_nonce()
        self.last_ping = time.time()
        ping = PingMessage(nonce=nonce)
        ping_msg = ping.to_network_message(self.network)
        await self.send_message(ping_msg)
        logger.debug(f"Sent ping to {self.host}:{self.port}")
    
    async def disconnect(self):
        """Disconnect from peer"""
        logger.info(f"Disconnecting from {self.host}:{self.port}")
        
        self.state = PeerState.DISCONNECTED
        
        # Cancel tasks
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        
        if self._ping_task:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass
        
        # Close connection
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing connection to {self.host}:{self.port}: {e}")
        
        self.reader = None
        self.writer = None
    
    def _generate_nonce(self) -> int:
        return random.randint(0, 2**64 - 1)
    
    def adjust_score(self, delta: int):
        """Adjust the peer's reputation score by *delta* (result clamped to [0, 100])."""
        self.score = max(0, min(100, self.score + delta))
        if self.score == 0:
            logger.warning(f"Peer {self.host}:{self.port} banned (score=0)")
    
    def is_connected(self) -> bool:
        """Check if peer is connected and ready"""
        return self.state == PeerState.READY
    
    def __repr__(self) -> str:
        direction = "in" if self.inbound else "out"
        relay = "block-only" if not self.relay_txs else "full"
        return f"Peer({self.host}:{self.port}, {direction}, {relay}, state={self.state.name}, score={self.score})"
