"""
Tor and I2P proxy support for anonymous P2P connections.

This module implements:
- Tor control protocol for creating ephemeral hidden services (ADD_ONION)
- SOCKS5 stream isolation for Tor circuit separation
- I2P SAM protocol for outbound and inbound connections

Reference: Bitcoin Core torcontrol.cpp, i2p.cpp
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, Dict, Callable

logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

# Tor control port defaults
DEFAULT_TOR_CONTROL_PORT = 9051
DEFAULT_TOR_SOCKS_PORT = 9050

# Tor control protocol
TOR_COOKIE_SIZE = 32
TOR_NONCE_SIZE = 32
TOR_REPLY_OK = 250
TOR_REPLY_ASYNC_EVENT = 650

# SOCKS5 constants (RFC 1928)
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USER_PASS = 0x02
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCESS = 0x00

# Tor-specific SOCKS5 error codes (for .onion connections)
SOCKS5_TOR_HS_DESC_NOT_FOUND = 0xF0
SOCKS5_TOR_HS_DESC_INVALID = 0xF1
SOCKS5_TOR_HS_INTRO_FAILED = 0xF2
SOCKS5_TOR_HS_REND_FAILED = 0xF3
SOCKS5_TOR_HS_MISSING_CLIENT_AUTH = 0xF4
SOCKS5_TOR_HS_WRONG_CLIENT_AUTH = 0xF5
SOCKS5_TOR_HS_BAD_ADDRESS = 0xF6
SOCKS5_TOR_HS_INTRO_TIMEOUT = 0xF7

# I2P SAM defaults
DEFAULT_I2P_SAM_PORT = 7656
I2P_SAM_MAX_MSG_SIZE = 65536


# ============================================================================
# Stream Isolation for Tor
# ============================================================================

class TorStreamIsolation:
    """
    Generate unique SOCKS5 credentials for Tor stream isolation.

    Each connection gets a unique username/password pair, causing Tor
    to use a different circuit for each connection (requires IsolateSOCKSAuth
    enabled in torrc, which is the default).

    Reference: Bitcoin Core netbase.cpp TorStreamIsolationCredentialsGenerator
    """

    def __init__(self):
        # Random 8-byte prefix generated at startup
        self._prefix = secrets.token_hex(8)
        self._counter = 0

    def generate(self) -> Tuple[str, str]:
        """Generate unique credentials for stream isolation."""
        cred = f"{self._prefix}-{self._counter}"
        self._counter += 1
        # Both username and password are the same (Tor ignores password value)
        return cred, cred


# Global stream isolation generator
_stream_isolation = TorStreamIsolation()


async def socks5_connect_isolated(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
    isolate: bool = True,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connect through SOCKS5 proxy with optional stream isolation.

    When isolate=True, uses unique credentials to force a different Tor circuit.
    This prevents correlation of connections through circuit analysis.

    Args:
        proxy_host: SOCKS5 proxy hostname
        proxy_port: SOCKS5 proxy port
        dest_host: Destination hostname (can be .onion)
        dest_port: Destination port
        timeout: Connection timeout in seconds
        isolate: If True, use stream isolation credentials

    Returns:
        (reader, writer) tuple for the tunneled connection
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        # Determine auth method
        if isolate:
            username, password = _stream_isolation.generate()
            methods = struct.pack("BBB", SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE)
            methods = struct.pack("BBBB", SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USER_PASS)
        else:
            methods = struct.pack("BBB", SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE)

        # Send greeting
        writer.write(methods)
        await writer.drain()

        # Read server's chosen method
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected version {resp[0]}")

        chosen_method = resp[1]

        if chosen_method == SOCKS5_AUTH_USER_PASS and isolate:
            # RFC 1929 username/password authentication
            auth_req = struct.pack("B", 0x01)  # auth version
            auth_req += struct.pack("B", len(username)) + username.encode()
            auth_req += struct.pack("B", len(password)) + password.encode()
            writer.write(auth_req)
            await writer.drain()

            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth_resp[1] != 0x00:
                raise Exception(f"SOCKS5: auth failed with status {auth_resp[1]}")
        elif chosen_method == SOCKS5_AUTH_NONE:
            pass  # No auth needed
        elif chosen_method == 0xFF:
            raise Exception("SOCKS5: no acceptable authentication method")
        else:
            raise Exception(f"SOCKS5: unexpected auth method {chosen_method}")

        # CONNECT request with domain name
        host_bytes = dest_host.encode("ascii")
        connect_req = struct.pack(
            "!BBBB",
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,
            SOCKS5_ATYP_DOMAINNAME,
        )
        connect_req += struct.pack("B", len(host_bytes)) + host_bytes
        connect_req += struct.pack("!H", dest_port)
        writer.write(connect_req)
        await writer.drain()

        # Read CONNECT reply
        reply_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if reply_header[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected reply version {reply_header[0]}")

        status = reply_header[1]
        if status != SOCKS5_REPLY_SUCCESS:
            error_msg = _socks5_error_message(status)
            raise Exception(f"SOCKS5: CONNECT failed: {error_msg} (0x{status:02x})")

        # Consume bind address
        atyp = reply_header[3]
        if atyp == SOCKS5_ATYP_IPV4:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_IPV6:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            dlen = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(dlen[0] + 2), timeout=timeout)

        logger.debug(f"SOCKS5 tunnel to {dest_host}:{dest_port} (isolated={isolate})")
        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


def _socks5_error_message(code: int) -> str:
    """Convert SOCKS5 error code to human-readable message."""
    errors = {
        0x01: "general failure",
        0x02: "connection not allowed",
        0x03: "network unreachable",
        0x04: "host unreachable",
        0x05: "connection refused",
        0x06: "TTL expired",
        0x07: "command not supported",
        0x08: "address type not supported",
        SOCKS5_TOR_HS_DESC_NOT_FOUND: "onion descriptor not found",
        SOCKS5_TOR_HS_DESC_INVALID: "onion descriptor invalid",
        SOCKS5_TOR_HS_INTRO_FAILED: "onion introduction failed",
        SOCKS5_TOR_HS_REND_FAILED: "onion rendezvous failed",
        SOCKS5_TOR_HS_MISSING_CLIENT_AUTH: "onion missing client auth",
        SOCKS5_TOR_HS_WRONG_CLIENT_AUTH: "onion wrong client auth",
        SOCKS5_TOR_HS_BAD_ADDRESS: "bad onion address",
        SOCKS5_TOR_HS_INTRO_TIMEOUT: "onion introduction timeout",
    }
    return errors.get(code, "unknown error")


# ============================================================================
# Tor Control Protocol
# ============================================================================

@dataclass
class TorControllerState:
    """State for Tor control connection."""
    connected: bool = False
    authenticated: bool = False
    service_id: Optional[str] = None  # e.g., "abc123...xyz"
    private_key: Optional[str] = None  # base64 encoded
    onion_address: Optional[str] = None  # e.g., "abc123...xyz.onion"


class TorController:
    """
    Tor control protocol client for creating hidden services.

    Supports:
    - NULL, HASHEDPASSWORD, and SAFECOOKIE authentication
    - ADD_ONION for ephemeral hidden service creation
    - Private key persistence across restarts

    Reference: Bitcoin Core torcontrol.cpp
    """

    def __init__(
        self,
        control_host: str = "127.0.0.1",
        control_port: int = DEFAULT_TOR_CONTROL_PORT,
        password: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        self._control_host = control_host
        self._control_port = control_port
        self._password = password
        self._data_dir = data_dir

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._state = TorControllerState()

        # Callbacks
        self._on_service_ready: Optional[Callable[[str], None]] = None

    @property
    def onion_address(self) -> Optional[str]:
        """The created onion address (e.g., 'xyz...abc.onion')."""
        return self._state.onion_address

    @property
    def is_connected(self) -> bool:
        """True if connected and authenticated to Tor control port."""
        return self._state.connected and self._state.authenticated

    async def connect(self) -> bool:
        """Connect to Tor control port and authenticate."""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._control_host, self._control_port),
                timeout=10.0,
            )
            self._state.connected = True
            logger.info(f"Connected to Tor control port {self._control_host}:{self._control_port}")

            # Authenticate
            await self._authenticate()
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Tor control: {e}")
            self._state.connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from Tor control port."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._state = TorControllerState()

    async def _send_command(self, cmd: str) -> Tuple[int, str]:
        """Send command and read response. Returns (reply_code, response_text)."""
        if not self._writer or not self._reader:
            raise Exception("Not connected to Tor control")

        self._writer.write((cmd + "\r\n").encode())
        await self._writer.drain()

        # Read multi-line response
        lines = []
        while True:
            line = await asyncio.wait_for(
                self._reader.readline(),
                timeout=30.0,
            )
            line = line.decode().rstrip("\r\n")
            if not line:
                raise Exception("Tor control: empty response")

            # Parse reply code
            try:
                code = int(line[:3])
            except ValueError:
                raise Exception(f"Tor control: invalid reply format: {line}")

            separator = line[3:4]
            content = line[4:]
            lines.append(content)

            if separator == " ":
                # Final line
                return code, "\n".join(lines)
            elif separator == "-":
                # More lines follow
                continue
            elif separator == "+":
                # Data follows until "."
                while True:
                    data_line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=30.0,
                    )
                    data_line = data_line.decode().rstrip("\r\n")
                    if data_line == ".":
                        break
                    lines.append(data_line)
            else:
                raise Exception(f"Tor control: unexpected separator: {separator}")

    async def _authenticate(self) -> None:
        """Authenticate with Tor using best available method."""
        # Get protocol info to determine auth methods
        code, response = await self._send_command("PROTOCOLINFO 1")
        if code != TOR_REPLY_OK:
            raise Exception(f"PROTOCOLINFO failed: {response}")

        # Parse available auth methods
        auth_methods = []
        cookie_file = None

        for line in response.split("\n"):
            if line.startswith("AUTH METHODS="):
                # Extract methods
                parts = line.split()
                methods_part = parts[0].split("=")[1]
                auth_methods = methods_part.split(",")
                # Look for cookie file
                for part in parts[1:]:
                    if part.startswith("COOKIEFILE="):
                        cookie_file = part.split("=", 1)[1].strip('"')

        logger.debug(f"Tor auth methods: {auth_methods}, cookie: {cookie_file}")

        # Try authentication methods in order of preference
        if "NULL" in auth_methods:
            await self._auth_null()
        elif "SAFECOOKIE" in auth_methods and cookie_file:
            await self._auth_safecookie(cookie_file)
        elif "HASHEDPASSWORD" in auth_methods and self._password:
            await self._auth_password()
        elif "COOKIE" in auth_methods and cookie_file:
            await self._auth_cookie(cookie_file)
        else:
            raise Exception(f"No supported Tor auth method: {auth_methods}")

        self._state.authenticated = True
        logger.info("Authenticated with Tor control")

    async def _auth_null(self) -> None:
        """NULL authentication (no credentials needed)."""
        code, response = await self._send_command("AUTHENTICATE")
        if code != TOR_REPLY_OK:
            raise Exception(f"NULL auth failed: {response}")

    async def _auth_password(self) -> None:
        """HASHEDPASSWORD authentication."""
        # Escape quotes in password
        escaped = self._password.replace('"', '\\"')
        code, response = await self._send_command(f'AUTHENTICATE "{escaped}"')
        if code != TOR_REPLY_OK:
            raise Exception(f"Password auth failed: {response}")

    async def _auth_cookie(self, cookie_file: str) -> None:
        """COOKIE authentication (simple cookie-based)."""
        try:
            with open(cookie_file, "rb") as f:
                cookie = f.read()
            if len(cookie) != TOR_COOKIE_SIZE:
                raise Exception(f"Invalid cookie size: {len(cookie)}")
        except IOError as e:
            raise Exception(f"Cannot read cookie file: {e}")

        code, response = await self._send_command(f"AUTHENTICATE {cookie.hex()}")
        if code != TOR_REPLY_OK:
            raise Exception(f"Cookie auth failed: {response}")

    async def _auth_safecookie(self, cookie_file: str) -> None:
        """SAFECOOKIE authentication (challenge-response)."""
        # Read cookie
        try:
            with open(cookie_file, "rb") as f:
                cookie = f.read()
            if len(cookie) != TOR_COOKIE_SIZE:
                raise Exception(f"Invalid cookie size: {len(cookie)}")
        except IOError as e:
            raise Exception(f"Cannot read cookie file: {e}")

        # Generate client nonce
        client_nonce = secrets.token_bytes(TOR_NONCE_SIZE)

        # Send challenge
        code, response = await self._send_command(
            f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}"
        )
        if code != TOR_REPLY_OK:
            raise Exception(f"AUTHCHALLENGE failed: {response}")

        # Parse response: SERVERHASH=... SERVERNONCE=...
        server_hash_hex = None
        server_nonce_hex = None
        for part in response.split():
            if part.startswith("SERVERHASH="):
                server_hash_hex = part.split("=")[1]
            elif part.startswith("SERVERNONCE="):
                server_nonce_hex = part.split("=")[1]

        if not server_hash_hex or not server_nonce_hex:
            raise Exception(f"Invalid AUTHCHALLENGE response: {response}")

        server_hash = bytes.fromhex(server_hash_hex)
        server_nonce = bytes.fromhex(server_nonce_hex)

        # Verify server hash
        expected_server_hash = hmac.new(
            b"Tor safe cookie authentication server-to-controller hash",
            cookie + client_nonce + server_nonce,
            hashlib.sha256,
        ).digest()

        if server_hash != expected_server_hash:
            raise Exception("SAFECOOKIE: server hash mismatch")

        # Compute client hash
        client_hash = hmac.new(
            b"Tor safe cookie authentication controller-to-server hash",
            cookie + client_nonce + server_nonce,
            hashlib.sha256,
        ).digest()

        # Authenticate with client hash
        code, response = await self._send_command(f"AUTHENTICATE {client_hash.hex()}")
        if code != TOR_REPLY_OK:
            raise Exception(f"SAFECOOKIE auth failed: {response}")

    async def create_hidden_service(self, target_port: int) -> Optional[str]:
        """
        Create an ephemeral hidden service pointing to target_port.

        Uses ADD_ONION to create a v3 (.onion) hidden service. The private key
        is persisted to disk so the same address is used across restarts.

        Args:
            target_port: Local port to forward connections to

        Returns:
            The .onion address (e.g., 'xyz...abc.onion') or None on failure
        """
        if not self.is_connected:
            return None

        # Try to load existing private key
        private_key = self._load_private_key()

        if private_key:
            # Use existing key
            cmd = f"ADD_ONION {private_key} Port={target_port},127.0.0.1:{target_port}"
        else:
            # Generate new Ed25519-V3 key
            cmd = f"ADD_ONION NEW:ED25519-V3 Port={target_port},127.0.0.1:{target_port}"

        code, response = await self._send_command(cmd)
        if code != TOR_REPLY_OK:
            logger.error(f"ADD_ONION failed: {response}")
            return None

        # Parse response
        service_id = None
        new_private_key = None

        for line in response.split("\n"):
            if line.startswith("ServiceID="):
                service_id = line.split("=")[1]
            elif line.startswith("PrivateKey="):
                new_private_key = line.split("=", 1)[1]

        if not service_id:
            logger.error(f"ADD_ONION: no ServiceID in response: {response}")
            return None

        # Save private key if new
        if new_private_key and not private_key:
            self._save_private_key(new_private_key)

        self._state.service_id = service_id
        self._state.private_key = new_private_key or private_key
        self._state.onion_address = f"{service_id}.onion"

        logger.info(f"Created hidden service: {self._state.onion_address}")

        if self._on_service_ready:
            self._on_service_ready(self._state.onion_address)

        return self._state.onion_address

    async def remove_hidden_service(self) -> bool:
        """Remove the hidden service."""
        if not self.is_connected or not self._state.service_id:
            return False

        code, response = await self._send_command(f"DEL_ONION {self._state.service_id}")
        if code != TOR_REPLY_OK:
            logger.warning(f"DEL_ONION failed: {response}")
            return False

        self._state.service_id = None
        self._state.onion_address = None
        return True

    def _private_key_path(self) -> Optional[Path]:
        """Path to the private key file."""
        if not self._data_dir:
            return None
        return Path(self._data_dir) / "onion_v3_private_key"

    def _load_private_key(self) -> Optional[str]:
        """Load private key from disk."""
        path = self._private_key_path()
        if not path or not path.exists():
            return None
        try:
            return path.read_text().strip()
        except Exception as e:
            logger.warning(f"Failed to load onion private key: {e}")
            return None

    def _save_private_key(self, key: str) -> None:
        """Save private key to disk."""
        path = self._private_key_path()
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically
            tmp = path.with_suffix(".tmp")
            tmp.write_text(key)
            tmp.replace(path)
            # Set restrictive permissions
            os.chmod(path, 0o600)
            logger.debug(f"Saved onion private key to {path}")
        except Exception as e:
            logger.warning(f"Failed to save onion private key: {e}")

    def set_service_ready_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback invoked when hidden service is ready."""
        self._on_service_ready = callback


# ============================================================================
# I2P SAM Protocol
# ============================================================================

def _i2p_b64_encode(data: bytes) -> str:
    """Encode bytes to I2P-style base64 (uses -~ instead of +/)."""
    standard = base64.b64encode(data).decode()
    return standard.replace("+", "-").replace("/", "~")


def _i2p_b64_decode(data: str) -> bytes:
    """Decode I2P-style base64 to bytes."""
    standard = data.replace("-", "+").replace("~", "/")
    return base64.b64decode(standard)


def i2p_destination_to_address(destination: bytes) -> str:
    """
    Convert an I2P destination to a .b32.i2p address.

    The address is the base32 encoding of the SHA256 hash of the destination.
    """
    h = hashlib.sha256(destination).digest()
    return base64.b32encode(h).decode().lower().rstrip("=") + ".b32.i2p"


@dataclass
class I2PSessionState:
    """State for an I2P SAM session."""
    connected: bool = False
    session_id: Optional[str] = None
    destination: Optional[str] = None  # base64 encoded
    address: Optional[str] = None  # .b32.i2p address


class I2PSession:
    """
    I2P SAM (Simple Anonymous Messaging) protocol client.

    Supports SAM 3.1 protocol:
    - HELLO handshake
    - SESSION CREATE for establishing streaming sessions
    - STREAM CONNECT for outbound connections
    - STREAM ACCEPT for inbound connections
    - NAMING LOOKUP for address resolution

    Reference: Bitcoin Core i2p.cpp
    """

    def __init__(
        self,
        sam_host: str = "127.0.0.1",
        sam_port: int = DEFAULT_I2P_SAM_PORT,
        data_dir: Optional[str] = None,
        persistent: bool = True,
    ):
        self._sam_host = sam_host
        self._sam_port = sam_port
        self._data_dir = data_dir
        self._persistent = persistent

        self._control_reader: Optional[asyncio.StreamReader] = None
        self._control_writer: Optional[asyncio.StreamWriter] = None
        self._state = I2PSessionState()

        # Accept socket for inbound connections
        self._accept_reader: Optional[asyncio.StreamReader] = None
        self._accept_writer: Optional[asyncio.StreamWriter] = None

    @property
    def address(self) -> Optional[str]:
        """The .b32.i2p address for this session."""
        return self._state.address

    @property
    def is_connected(self) -> bool:
        """True if SAM session is established."""
        return self._state.connected and self._state.session_id is not None

    async def connect(self) -> bool:
        """Connect to SAM bridge and create a session."""
        try:
            self._control_reader, self._control_writer = await asyncio.wait_for(
                asyncio.open_connection(self._sam_host, self._sam_port),
                timeout=10.0,
            )
            self._state.connected = True

            # SAM HELLO handshake
            await self._hello()

            # Create streaming session
            await self._create_session()

            logger.info(f"I2P session created: {self._state.address}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to I2P SAM: {e}")
            await self.disconnect()
            return False

    async def disconnect(self) -> None:
        """Disconnect from SAM bridge."""
        for writer in [self._control_writer, self._accept_writer]:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        self._control_reader = None
        self._control_writer = None
        self._accept_reader = None
        self._accept_writer = None
        self._state = I2PSessionState()

    async def _send_command(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cmd: str,
    ) -> Dict[str, str]:
        """Send SAM command and parse response."""
        writer.write((cmd + "\n").encode())
        await writer.drain()

        # Read response (single line, space-separated key=value pairs)
        line = await asyncio.wait_for(
            reader.readline(),
            timeout=180.0,  # I2P can be slow
        )
        line = line.decode().strip()

        if not line:
            raise Exception("I2P SAM: empty response")

        # Parse response
        parts = line.split()
        result: Dict[str, str] = {}

        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                result[key] = value
            else:
                result[part] = ""

        return result

    async def _hello(self) -> None:
        """SAM HELLO handshake."""
        resp = await self._send_command(
            self._control_reader,
            self._control_writer,
            "HELLO VERSION MIN=3.1 MAX=3.1",
        )

        if resp.get("RESULT") != "OK":
            raise Exception(f"I2P HELLO failed: {resp}")

        logger.debug(f"I2P SAM version: {resp.get('VERSION', 'unknown')}")

    async def _create_session(self) -> None:
        """Create a streaming session."""
        session_id = secrets.token_hex(8)

        # Try to load existing private key for persistent sessions
        private_key = None
        if self._persistent:
            private_key = self._load_private_key()

        if private_key:
            # Use existing key
            destination = private_key
        else:
            # Generate new key
            destination = "TRANSIENT SIGNATURE_TYPE=7"

        cmd = (
            f"SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={destination} "
            "i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3"
        )

        resp = await self._send_command(
            self._control_reader,
            self._control_writer,
            cmd,
        )

        if resp.get("RESULT") != "OK":
            raise Exception(f"I2P SESSION CREATE failed: {resp}")

        self._state.session_id = session_id

        # Get destination from response
        dest_b64 = resp.get("DESTINATION")
        if dest_b64:
            self._state.destination = dest_b64
            dest_bytes = _i2p_b64_decode(dest_b64)
            self._state.address = i2p_destination_to_address(dest_bytes)

            # Save private key if this is a new persistent session
            if self._persistent and not private_key:
                self._save_private_key(dest_b64)

    async def stream_connect(
        self,
        dest_address: str,
        timeout: float = 180.0,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to an I2P destination.

        Args:
            dest_address: .b32.i2p address or full destination
            timeout: Connection timeout in seconds

        Returns:
            (reader, writer) tuple for the stream
        """
        if not self.is_connected:
            raise Exception("I2P session not connected")

        # Open new connection to SAM for this stream
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._sam_host, self._sam_port),
            timeout=10.0,
        )

        try:
            # HELLO on new connection
            hello_resp = await self._send_command(reader, writer, "HELLO VERSION MIN=3.1 MAX=3.1")
            if hello_resp.get("RESULT") != "OK":
                raise Exception(f"I2P HELLO failed: {hello_resp}")

            # Resolve address if needed
            if dest_address.endswith(".b32.i2p") or dest_address.endswith(".i2p"):
                lookup_resp = await self._send_command(
                    reader, writer,
                    f"NAMING LOOKUP NAME={dest_address}",
                )
                if lookup_resp.get("RESULT") != "OK":
                    raise Exception(f"I2P NAMING LOOKUP failed: {lookup_resp}")
                destination = lookup_resp.get("VALUE", dest_address)
            else:
                destination = dest_address

            # STREAM CONNECT
            connect_resp = await self._send_command(
                reader, writer,
                f"STREAM CONNECT ID={self._state.session_id} DESTINATION={destination} SILENT=false",
            )

            result = connect_resp.get("RESULT")
            if result != "OK":
                if result == "CANT_REACH_PEER":
                    raise Exception(f"I2P: cannot reach peer {dest_address}")
                elif result == "TIMEOUT":
                    raise Exception(f"I2P: connection timeout to {dest_address}")
                else:
                    raise Exception(f"I2P STREAM CONNECT failed: {connect_resp}")

            logger.debug(f"I2P stream connected to {dest_address}")
            return reader, writer

        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def stream_accept(
        self,
        timeout: float = 0,
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter, str]]:
        """
        Accept an incoming I2P connection.

        Args:
            timeout: Timeout in seconds (0 = no timeout)

        Returns:
            (reader, writer, peer_destination) or None on timeout
        """
        if not self.is_connected:
            raise Exception("I2P session not connected")

        # Open new connection for accepting
        if not self._accept_reader:
            self._accept_reader, self._accept_writer = await asyncio.wait_for(
                asyncio.open_connection(self._sam_host, self._sam_port),
                timeout=10.0,
            )

            # HELLO
            hello_resp = await self._send_command(
                self._accept_reader,
                self._accept_writer,
                "HELLO VERSION MIN=3.1 MAX=3.1",
            )
            if hello_resp.get("RESULT") != "OK":
                raise Exception(f"I2P HELLO failed: {hello_resp}")

        # STREAM ACCEPT (blocking until connection)
        cmd = f"STREAM ACCEPT ID={self._state.session_id} SILENT=false"
        self._accept_writer.write((cmd + "\n").encode())
        await self._accept_writer.drain()

        # Wait for incoming connection
        try:
            if timeout > 0:
                line = await asyncio.wait_for(
                    self._accept_reader.readline(),
                    timeout=timeout,
                )
            else:
                line = await self._accept_reader.readline()
        except asyncio.TimeoutError:
            return None

        line = line.decode().strip()
        parts = dict(p.split("=", 1) for p in line.split() if "=" in p)

        result = parts.get("RESULT") or line.split()[1] if len(line.split()) > 1 else None
        if result != "OK":
            raise Exception(f"I2P STREAM ACCEPT failed: {line}")

        peer_dest = parts.get("DESTINATION", "unknown")

        # The accept socket is now the stream socket
        reader = self._accept_reader
        writer = self._accept_writer
        self._accept_reader = None
        self._accept_writer = None

        logger.debug(f"I2P accepted connection from {peer_dest[:32]}...")
        return reader, writer, peer_dest

    def _private_key_path(self) -> Optional[Path]:
        """Path to the I2P private key file."""
        if not self._data_dir:
            return None
        return Path(self._data_dir) / "i2p_private_key"

    def _load_private_key(self) -> Optional[str]:
        """Load I2P private key from disk."""
        path = self._private_key_path()
        if not path or not path.exists():
            return None
        try:
            return path.read_text().strip()
        except Exception as e:
            logger.warning(f"Failed to load I2P private key: {e}")
            return None

    def _save_private_key(self, key: str) -> None:
        """Save I2P private key to disk."""
        path = self._private_key_path()
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(key)
            tmp.replace(path)
            os.chmod(path, 0o600)
            logger.debug(f"Saved I2P private key to {path}")
        except Exception as e:
            logger.warning(f"Failed to save I2P private key: {e}")


# ============================================================================
# Utility Functions
# ============================================================================

def is_i2p_host(host: str) -> bool:
    """Return True if host is an I2P address."""
    return host.lower().endswith(".i2p")


def is_onion_host(host: str) -> bool:
    """Return True if host is a Tor .onion address."""
    return host.lower().endswith(".onion")


def is_anonymous_network(host: str) -> bool:
    """Return True if host is on Tor or I2P."""
    return is_onion_host(host) or is_i2p_host(host)
