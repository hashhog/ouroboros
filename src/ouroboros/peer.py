"""
Bitcoin peer connection management.

This module implements peer-to-peer connection management with asyncio,
including connection, handshake, message handling, and error recovery.
"""

import asyncio
import struct
import hashlib
import time
import random
import logging
from typing import Optional, Callable, Dict
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
)

logger = logging.getLogger(__name__)


class PeerState(Enum):
    """Peer connection state"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    HANDSHAKING = 3
    READY = 4


class Peer:
    """Manages connection to a single Bitcoin peer"""
    
    def __init__(self, host: str, port: int, network: str = "mainnet"):
        """
        Initialize peer connection.
        
        Args:
            host: Peer hostname or IP address
            port: Peer port number
            network: Network name (mainnet, testnet, regtest)
        """
        self.host = host
        self.port = port
        self.network = network
        self.state = PeerState.DISCONNECTED
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        
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
        
        # Connection retry settings
        self._retry_count = 0
        self._max_retries = 3
        self._retry_delay = 5.0  # seconds
    
    async def connect(self, start_height: int = 0, retry: bool = True) -> bool:
        """
        Connect to peer and complete handshake.
        
        Args:
            start_height: Our blockchain height for version message
            retry: Whether to retry on failure
            
        Returns:
            True if connection successful, False otherwise
        """
        max_attempts = self._max_retries + 1 if retry else 1
        
        for attempt in range(max_attempts):
            try:
                logger.info(f"Connecting to {self.host}:{self.port} (attempt {attempt + 1}/{max_attempts})")
                self.state = PeerState.CONNECTING
                
                # Establish TCP connection with timeout
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=10.0
                )
                
                self.state = PeerState.CONNECTED
                
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
    
    async def _handshake(self, start_height: int):
        """Perform version handshake"""
        self.state = PeerState.HANDSHAKING
        
        # Create network addresses
        # For simplicity, we'll use IPv4-mapped IPv6 addresses
        addr_recv = self._create_network_address(self.host, self.port)
        addr_from = self._create_network_address("0.0.0.0", 8333)
        
        # Send version message
        version_msg = VersionMessage(
            version=70015,
            services=1,
            timestamp=int(time.time()),
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=self._generate_nonce(),
            user_agent="/bitcoin-hybrid:0.1.0/",
            start_height=start_height,
            relay=True
        )
        
        await self.send_message(version_msg.to_network_message(self.network))
        
        # Receive version message
        msg = await self.receive_message(timeout=30.0)
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")
        
        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        
        # Send verack
        verack = NetworkMessage(command="verack", payload=b"", magic=get_magic(self.network))
        await self.send_message(verack)
        
        # Receive verack
        msg = await self.receive_message(timeout=30.0)
        if msg.command != "verack":
            raise Exception(f"Expected verack, got {msg.command}")
    
    def _create_network_address(self, host: str, port: int) -> NetworkAddress:
        """
        Create network address from host and port.
        
        Args:
            host: Hostname or IP address
            port: Port number
            
        Returns:
            NetworkAddress instance
        """
        # Try to parse as IPv4
        try:
            parts = host.split('.')
            if len(parts) == 4:
                # Validate all parts are integers
                for p in parts:
                    int(p)
                # Use helper method
                return NetworkAddress.from_ipv4(host, port, services=1)
        except (ValueError, AttributeError):
            pass
        
        # Default to all zeros (unknown address)
        return NetworkAddress(services=1, ip=b'\x00' * 16, port=port)
    
    async def send_message(self, msg: NetworkMessage):
        """
        Send a message to peer.
        
        Args:
            msg: NetworkMessage to send
        """
        if self.state != PeerState.READY and self.state != PeerState.HANDSHAKING:
            raise Exception(f"Cannot send message in state {self.state}")
        
        if not self.writer:
            raise Exception("Not connected")
        
        data = msg.serialize()
        self.writer.write(data)
        await self.writer.drain()
        
        logger.debug(f"Sent {msg.command} to {self.host}:{self.port}")
    
    async def receive_message(self, timeout: float = 30.0) -> NetworkMessage:
        """
        Receive a message from peer.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            NetworkMessage instance
            
        Raises:
            asyncio.TimeoutError: If timeout exceeded
            Exception: If message format is invalid
        """
        if not self.reader:
            raise Exception("Not connected")
        
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
    
    async def listen(self):
        """
        Listen for messages and dispatch to handlers.
        
        This method runs in a loop until the peer disconnects.
        """
        try:
            while self.state == PeerState.READY:
                try:
                    msg = await self.receive_message(timeout=60.0)
                    
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
        """Periodically send ping messages"""
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
        """
        Register message handler.
        
        Args:
            command: Message command name (e.g., "inv", "block", "tx")
            handler: Async function that takes a NetworkMessage as argument
        """
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
        """Generate random nonce"""
        return random.randint(0, 2**64 - 1)
    
    def adjust_score(self, delta: int):
        """
        Adjust peer reputation score.
        
        Args:
            delta: Score change (positive or negative)
        """
        self.score = max(0, min(100, self.score + delta))
        if self.score == 0:
            logger.warning(f"Peer {self.host}:{self.port} banned (score=0)")
    
    def is_connected(self) -> bool:
        """Check if peer is connected and ready"""
        return self.state == PeerState.READY
    
    def __repr__(self) -> str:
        """String representation"""
        return f"Peer({self.host}:{self.port}, state={self.state.name}, score={self.score})"
