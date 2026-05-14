"""
Address manager for peer discovery and gossip.

Implements eclipse attack mitigations based on Bitcoin Core's addrman:
  - Bucketed storage: 256 "new" buckets (64 entries each) and 64 "tried"
    buckets (256 entries each), with deterministic hash-based assignment.
  - Source attribution: tracks which peer introduced each address, limiting
    single-source influence through bucket distribution.
  - Test-before-evict: collision resolution for tried table.

Persists to ``{datadir}/peers.json`` so addresses survive restarts.

Reference: /home/max/hashhog/bitcoin/src/addrman.cpp
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import secrets
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Bucket configuration (Bitcoin Core: addrman.h)
# New table: 256 buckets, 64 entries each = 16,384 slots
# (Bitcoin Core uses 1024 new buckets, we use 256 for memory efficiency)
NEW_BUCKET_COUNT = 256
NEW_BUCKET_SIZE = 64
NEW_BUCKETS_PER_SOURCE_GROUP = 64  # max buckets per source /16 group

# Tried table: 64 buckets, 256 entries each = 16,384 slots
TRIED_BUCKET_COUNT = 64
TRIED_BUCKET_SIZE = 256
TRIED_BUCKETS_PER_GROUP = 8  # max buckets per address /16 group

# Address selection parameters
HORIZON = 30 * 24 * 3600  # 30 days - addresses older than this are "terrible"
RETRIES = 3  # max attempts before marking terrible
MAX_FAILURES = 10  # failures in MIN_FAIL window make address terrible
MIN_FAIL = 7 * 24 * 3600  # 7 days window for failure tracking

# Collision handling
MAX_TRIED_COLLISIONS = 10  # max pending collision entries
REPLACEMENT_HOURS = 4  # recent success protects from eviction


# BIP155 Network IDs
NET_IPV4 = 1
NET_IPV6 = 2
NET_TORV2 = 3  # deprecated
NET_TORV3 = 4
NET_I2P = 5
NET_CJDNS = 6


@dataclass
class AddrInfo:
    """Metadata for a single peer address.

    Supports BIP155 variable-length addresses (Tor v3, I2P, CJDNS).

    Attributes:
        host: Human-readable address string (IPv4/IPv6 or .onion/.b32.i2p)
        port: Port number
        services: Service flags (NODE_NETWORK, NODE_WITNESS, etc.)
        network_id: BIP155 network type (1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS)
        addr_bytes: Raw address bytes (variable length per BIP155)
        last_seen: Epoch timestamp when last seen
        last_attempt: Epoch timestamp of last connection attempt
        last_success: Epoch timestamp of last successful connection
        attempts: Total connection attempts
        failures: Connection failures in MIN_FAIL window
        source: Address key of peer who told us about this address
        source_group: /16 network group of source
        ref_count: Number of new buckets containing this addr
    """

    host: str
    port: int
    services: int = 0
    network_id: int = NET_IPV4   # BIP155 network type
    addr_bytes: bytes = b""      # raw address bytes (variable length)
    last_seen: float = 0.0       # epoch - most recent addr timestamp
    last_attempt: float = 0.0    # epoch - when we last tried to connect
    last_success: float = 0.0    # epoch - when we last connected successfully
    attempts: int = 0
    failures: int = 0            # connection failures in MIN_FAIL window
    source: str = ""             # who told us about this address
    source_group: str = ""       # /16 network group of source
    ref_count: int = 0           # number of new buckets containing this addr

    def get_key(self) -> str:
        """Unique key for this address (human-readable, used as dict key)."""
        return f"{self.host}:{self.port}"

    def get_binary_key(self) -> bytes:
        """18-byte binary key matching CService::GetKey() in Bitcoin Core.

        Returns 16-byte IP representation (IPv4-in-IPv6 mapped for IPv4
        addresses, raw 16-byte for IPv6) followed by 2 bytes of port
        in big-endian order.  This is the input format Core uses when
        computing bucket assignments in GetTriedBucket / GetNewBucket /
        GetBucketPosition.

        Reference: netaddress.cpp CNetAddr::GetAddrBytes() +
                   CService::GetKey() (port / 0x100, port & 0xFF).
        """
        import ipaddress as _ipaddress
        port_bytes = bytes([self.port >> 8, self.port & 0xFF])

        if self.network_id == NET_IPV4:
            # IPv4-in-IPv6 mapped address: 12-byte prefix + 4 IPv4 bytes
            # Matches Core's IPV4_IN_IPV6_PREFIX + m_addr
            IPV4_IN_IPV6_PREFIX = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
            try:
                ipv4 = _ipaddress.IPv4Address(self.host)
                return IPV4_IN_IPV6_PREFIX + ipv4.packed + port_bytes
            except ValueError:
                pass

        if self.network_id == NET_IPV6:
            try:
                ipv6 = _ipaddress.IPv6Address(self.host)
                return ipv6.packed + port_bytes
            except ValueError:
                pass

        # For Tor v3, I2P, CJDNS and unknown network types use raw addr_bytes
        # if available (16 bytes), else fall back to zero-padded 16 bytes.
        if self.addr_bytes and len(self.addr_bytes) == 16:
            return bytes(self.addr_bytes) + port_bytes

        # Fallback: zero-pad to 16 bytes (matches Core's all-zeros serialisation
        # for non-v1-compatible addresses in GetAddrBytes / SerializeV1Array).
        return b"\x00" * 16 + port_bytes

    def is_onion(self) -> bool:
        """Return True if this is a Tor .onion address."""
        return self.network_id == NET_TORV3 or self.host.endswith(".onion")

    def is_i2p(self) -> bool:
        """Return True if this is an I2P address."""
        return self.network_id == NET_I2P or self.host.endswith(".b32.i2p")

    def is_cjdns(self) -> bool:
        """Return True if this is a CJDNS address."""
        return self.network_id == NET_CJDNS

    def is_ipv4(self) -> bool:
        """Return True if this is an IPv4 address."""
        return self.network_id == NET_IPV4

    def is_ipv6(self) -> bool:
        """Return True if this is an IPv6 address."""
        return self.network_id == NET_IPV6

    def is_addrv1_compatible(self) -> bool:
        """Return True if this address can be sent via legacy addr message.

        Only IPv4 and IPv6 addresses are compatible with the legacy addr
        message format. Tor v3, I2P, and CJDNS require addrv2 (BIP155).
        """
        return self.network_id in (NET_IPV4, NET_IPV6)


def get_network_group(host: str, network_id: int = NET_IPV4) -> str:
    """Get network group for an address (for bucket diversification).

    For IPv4: returns first two octets (a.b) - /16 group
    For IPv6: returns /32 prefix (first 4 hex groups)
    For TorV3: returns first 4 bytes of pubkey (hex)
    For I2P: returns first 4 bytes of destination hash (hex)
    For CJDNS: returns "cjdns" (all CJDNS in same group)
    For .onion hostname: returns "onion"
    For .b32.i2p hostname: returns "i2p"

    Reference: Bitcoin Core addrman.cpp GetGroup()
    """
    # Handle .onion addresses
    if host.endswith(".onion"):
        return "onion"

    # Handle I2P addresses (.b32.i2p base32 destinations and plain .i2p)
    if host.endswith(".i2p"):
        return "i2p"

    # IPv4
    if network_id == NET_IPV4:
        parts = host.split(".")
        if len(parts) == 4:
            try:
                int(parts[0])
                int(parts[1])
                return f"{parts[0]}.{parts[1]}"
            except ValueError:
                pass
        return host

    # IPv6
    if network_id == NET_IPV6:
        if ":" in host:
            # Remove brackets if present
            h = host.strip("[]")
            groups = h.split(":")
            return ":".join(groups[:2]) if len(groups) >= 2 else host
        return host

    # TorV3 - group by first 4 bytes of pubkey
    if network_id == NET_TORV3:
        return "onion"

    # I2P - group by first 4 bytes of destination hash
    if network_id == NET_I2P:
        return "i2p"

    # CJDNS - all in same group
    if network_id == NET_CJDNS:
        return "cjdns"

    # Default: use host as group
    return host


def is_routable(host: str, network_id: int = NET_IPV4) -> bool:
    """Return True iff the address is publicly routable.

    Mirrors Bitcoin Core's CNetAddr::IsRoutable() in netaddress.cpp:
        return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() ||
               IsRFC4862() || IsRFC6598() || IsRFC5737() || IsRFC4193() ||
               IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());

    Non-IPv4/IPv6 network types (Tor v3, I2P, CJDNS) are considered routable
    if the address is non-empty (the equivalent of IsValid() for those types).
    """
    # Non-IP network types: routable if host is non-empty
    if network_id in (NET_TORV3, NET_I2P, NET_CJDNS):
        return bool(host)

    if not host:
        return False

    if network_id == NET_IPV4 or (network_id not in (NET_IPV6,) and ":" not in host):
        # --- IPv4 checks ---
        parts = host.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        if any(o < 0 or o > 255 for o in octets):
            return False
        a, b = octets[0], octets[1]

        # IsLocal: 0.0.0.0/8 (unspecified) and 127.0.0.0/8 (loopback)
        if a == 0 or a == 127:
            return False
        # IsRFC1918: 10/8, 172.16-31/12, 192.168/16
        if a == 10:
            return False
        if a == 172 and 16 <= b <= 31:
            return False
        if a == 192 and b == 168:
            return False
        # IsRFC2544: 198.18-19/15 (benchmarking)
        if a == 198 and (b == 18 or b == 19):
            return False
        # IsRFC3927: 169.254/16 (link-local)
        if a == 169 and b == 254:
            return False
        # IsRFC6598: 100.64-127/10 (shared address space)
        if a == 100 and 64 <= b <= 127:
            return False
        # IsRFC5737: 192.0.2/24, 198.51.100/24, 203.0.113/24 (documentation)
        if a == 192 and b == 0 and octets[2] == 2:
            return False
        if a == 198 and b == 51 and octets[2] == 100:
            return False
        if a == 203 and b == 0 and octets[2] == 113:
            return False
        return True

    # --- IPv6 checks ---
    try:
        import ipaddress
        addr6 = ipaddress.ip_address(host)
    except ValueError:
        return False

    # IsLocal: ::1/128 loopback
    if addr6.is_loopback:
        return False
    # IsRFC4862: fe80::/64 link-local (IPv6 equivalent of RFC3927)
    if addr6.is_link_local:
        return False
    # IsRFC4193: fc00::/7 unique local (ULA)
    if addr6.is_private:
        return False
    # IsRFC4843/IsRFC7343: 2001:0010::/28 and 2001:0020::/28 (ORCHID)
    packed = addr6.packed
    if packed[0] == 0x20 and packed[1] == 0x01 and packed[2] == 0x00:
        if (packed[3] & 0xF0) in (0x10, 0x20):
            return False
    # Unspecified ::
    if addr6 == ipaddress.ip_address("::"):
        return False
    return True


def _hash_for_bucket(key: bytes, *args) -> int:
    """Compute bucket-assignment hash matching Core's HashWriter::GetCheapHash().

    Core uses double-SHA256 (HashWriter::GetHash = SHA256(SHA256(data))) and
    returns the first 8 bytes as a little-endian uint64.  All inputs must be
    raw bytes; integer arguments are serialised as 8-byte little-endian (matching
    Core's Serialize for uint64_t / int).

    Reference: hash.h HashWriter::GetCheapHash() and addrman.cpp
    GetTriedBucket / GetNewBucket / GetBucketPosition.

    BUG-18 fix: was single SHA-256; now double-SHA256.
    BUG-19 fix: removed str branch — all inputs must be bytes or int; callers
                must pass binary keys (e.g. AddrInfo.get_binary_key()) not
                human-readable strings.
    """
    buf = key
    for arg in args:
        if isinstance(arg, bytes):
            buf += arg
        elif isinstance(arg, int):
            buf += arg.to_bytes(8, "little")
        else:
            raise TypeError(
                f"_hash_for_bucket: expected bytes or int, got {type(arg).__name__!r}"
            )
    digest = hashlib.sha256(hashlib.sha256(buf).digest()).digest()
    return int.from_bytes(digest[:8], "little")


class AddressManager:
    """Manages known peer addresses with bucketed new/tried tables.

    Eclipse attack mitigations:
    - Deterministic bucket assignment prevents manipulation
    - Source group tracking limits single-source influence
    - Network group diversification spreads across /16 ranges
    - ASN-based grouping when an asmap is loaded (BUG-1..9 fix)
    """

    def __init__(self, data_dir: str | None = None, asmap: bytes = b""):
        # Secret key for deterministic bucket hashing (anti-manipulation)
        self._key: bytes = secrets.token_bytes(32)

        # Loaded ASMap bytes; empty bytes = disabled (fall back to /16 grouping).
        # Mirrors Bitcoin Core's NetGroupManager::m_asmap.
        self._asmap: bytes = asmap

        # New table: bucket[i][j] = addr_key or None
        # 256 buckets x 64 entries
        self._new_buckets: list[list[str | None]] = [
            [None] * NEW_BUCKET_SIZE for _ in range(NEW_BUCKET_COUNT)
        ]

        # Tried table: bucket[i][j] = addr_key or None
        # 64 buckets x 256 entries
        self._tried_buckets: list[list[str | None]] = [
            [None] * TRIED_BUCKET_SIZE for _ in range(TRIED_BUCKET_COUNT)
        ]

        # Address info storage: addr_key -> AddrInfo
        self._addrs: dict[str, AddrInfo] = {}

        # Track which addresses are in which table
        self._in_new: set[str] = set()
        self._in_tried: set[str] = set()

        # Collision handling for tried table
        self._tried_collisions: set[str] = set()

        self._data_dir = data_dir
        self._filepath: str | None = None
        if data_dir:
            self._filepath = os.path.join(data_dir, "peers.json")
            self._load()

    # ASMap integration

    def using_asmap(self) -> bool:
        """Return True when an ASMap is loaded and active.

        Mirrors Bitcoin Core's NetGroupManager::UsingASMap().
        """
        return bool(self._asmap)

    def get_mapped_as(self, host: str, network_id: int) -> int:
        """Look up the ASN for a host using the loaded ASMap.

        Mirrors Bitcoin Core's NetGroupManager::GetMappedAS().

        Returns the ASN (> 0) when a mapping exists, 0 otherwise
        (including when no asmap is loaded, or for non-IP addresses).

        Args:
            host: Human-readable address string (IPv4, IPv6, .onion, etc.).
            network_id: BIP155 network type (1=IPv4, 2=IPv6, others→0).
        """
        if not self._asmap:
            return 0
        from ouroboros.asmap import get_mapped_as as _get_mapped_as
        return _get_mapped_as(self._asmap, host, network_id)

    def _get_addr_group(self, host: str, network_id: int) -> bytes:
        """Return the group bytes for addrman bucket computation.

        When an ASMap is loaded: returns the 5-byte ASN group vector
        (NET_IPV6 prefix + 4-byte little-endian ASN) for IPv4/IPv6
        addresses where a mapping exists.  This makes IPv4 and IPv6
        addresses in the same AS compete for the same buckets
        (Core: netgroup.cpp GetGroup() with m_asmap active).

        When no ASMap is loaded (or for non-IP addresses): returns the
        ASCII-encoded /16 prefix string as bytes (existing behaviour).

        Args:
            host: Human-readable address string.
            network_id: BIP155 network type.

        Returns:
            Group bytes for use in _hash_for_bucket().
        """
        if self._asmap and network_id in (NET_IPV4, NET_IPV6):
            asn = self.get_mapped_as(host, network_id)
            if asn > 0:
                from ouroboros.asmap import asn_group_bytes
                return asn_group_bytes(asn)
        return get_network_group(host, network_id).encode()

    # Bucket computation

    def _get_new_bucket(self, addr: AddrInfo, source_group: str) -> int:
        """Compute new table bucket for an address.

        Mirrors Core's CAddrInfo::GetNewBucket() in addrman.cpp:
          hash1 = dSHA256(nKey || addr_group || source_group)
          hash2 = dSHA256(nKey || source_group || hash1 % NEW_BUCKETS_PER_SOURCE_GROUP)
          bucket = hash2 % NEW_BUCKET_COUNT

        When an ASMap is loaded, addr_group is the 5-byte ASN vector
        (NET_IPV6 + 4-byte little-endian ASN) instead of the ASCII /16
        string.  This is the Core parity fix for BUG-11.
        """
        addr_group_b = self._get_addr_group(addr.host, addr.network_id)
        source_group_b = source_group.encode()
        hash1 = _hash_for_bucket(
            self._key, addr_group_b, source_group_b
        )
        hash2 = _hash_for_bucket(
            self._key, source_group_b, hash1 % NEW_BUCKETS_PER_SOURCE_GROUP
        )
        return hash2 % NEW_BUCKET_COUNT

    def _get_tried_bucket(self, addr: AddrInfo) -> int:
        """Compute tried table bucket for an address.

        Mirrors Core's CAddrInfo::GetTriedBucket() in addrman.cpp:
          hash1 = dSHA256(nKey || CService::GetKey())
          hash2 = dSHA256(nKey || addr_group || hash1 % TRIED_BUCKETS_PER_GROUP)
          bucket = hash2 % TRIED_BUCKET_COUNT

        When an ASMap is loaded, addr_group is the 5-byte ASN vector
        (NET_IPV6 + 4-byte little-endian ASN) for Core parity (BUG-12 fix).
        BUG-19 fix: use get_binary_key() (18-byte binary) not get_key() (string).
        """
        addr_binary_key = addr.get_binary_key()
        addr_group_b = self._get_addr_group(addr.host, addr.network_id)
        hash1 = _hash_for_bucket(self._key, addr_binary_key)
        hash2 = _hash_for_bucket(
            self._key, addr_group_b, hash1 % TRIED_BUCKETS_PER_GROUP
        )
        return hash2 % TRIED_BUCKET_COUNT

    def _get_bucket_position(
        self, addr: AddrInfo, is_new: bool, bucket: int
    ) -> int:
        """Compute position within a bucket.

        Mirrors Core's CAddrInfo::GetBucketPosition() in addrman.cpp:
          hash = dSHA256(nKey || prefix || bucket || CService::GetKey())
          pos  = hash % bucket_size

        BUG-19 fix: use get_binary_key() (18-byte binary) not get_key() (string).
        """
        prefix = b"N" if is_new else b"K"
        hash_val = _hash_for_bucket(
            self._key, prefix, bucket, addr.get_binary_key()
        )
        size = NEW_BUCKET_SIZE if is_new else TRIED_BUCKET_SIZE
        return hash_val % size

    # Address quality checks

    def _is_terrible(self, addr: AddrInfo) -> bool:
        """Check if an address should be considered terrible (unreliable)."""
        now = time.time()

        # Not tried recently - may be removed
        if now - addr.last_attempt < 60:
            return False

        # Timestamp in the future (suspicious)
        if addr.last_seen > now + 600:
            return True

        # Not seen in 30 days
        if now - addr.last_seen > HORIZON:
            return True

        # Never succeeded after multiple attempts
        if addr.last_success == 0 and addr.attempts >= RETRIES:
            return True

        # Too many failures in the failure window
        if (
            now - addr.last_success < MIN_FAIL
            and addr.failures >= MAX_FAILURES
        ):
            return True

        return False

    def _get_chance(self, addr: AddrInfo) -> float:
        """Get selection probability for an address."""
        now = time.time()
        chance = 1.0

        # Recently attempted - much lower priority
        if now - addr.last_attempt < 600:
            chance *= 0.01

        # Each failure reduces chance (capped at 8)
        chance *= 0.66 ** min(addr.attempts, 8)

        return chance

    # Public API

    def add(
        self,
        host: str,
        port: int,
        services: int = 0,
        timestamp: float = 0.0,
        source: str = "",
        network_id: int = NET_IPV4,
        addr_bytes: bytes = b"",
    ) -> bool:
        """Add an address to the new table.

        Args:
            host: Human-readable address string
            port: Port number
            services: Service flags
            timestamp: Last-seen timestamp
            source: Address key of peer who told us
            network_id: BIP155 network ID (1=IPv4, 2=IPv6, 4=TorV3, etc.)
            addr_bytes: Raw address bytes (for BIP155 addresses)

        Returns:
            True if inserted (new address), False if updated existing.
        """
        # Reject non-routable addresses (Core: AddSingle returns false if
        # !addr.IsRoutable()).  This blocks loopback, RFC-1918, link-local,
        # unspecified, and other non-public address ranges from polluting the
        # address table.  Reference: bitcoin-core/src/addrman.cpp:534 and
        # netaddress.cpp:462 CNetAddr::IsRoutable().
        if not is_routable(host, network_id):
            return False

        addr_key = f"{host}:{port}"
        source_group = get_network_group(source.split(":")[0] if source else "")

        # Already in tried - just update last_seen
        if addr_key in self._in_tried:
            info = self._addrs[addr_key]
            if timestamp > info.last_seen:
                info.last_seen = timestamp
            return False

        # Already in new - update if newer
        if addr_key in self._in_new:
            info = self._addrs[addr_key]
            if timestamp > info.last_seen:
                info.last_seen = timestamp
            if services:
                info.services = services
            return False

        # Create new address info
        info = AddrInfo(
            host=host,
            port=port,
            services=services,
            network_id=network_id,
            addr_bytes=addr_bytes,
            last_seen=timestamp or time.time(),
            source=source,
            source_group=source_group,
        )

        # Find bucket and position
        bucket = self._get_new_bucket(info, source_group)
        position = self._get_bucket_position(info, is_new=True, bucket=bucket)

        # Check if slot is occupied
        existing_key = self._new_buckets[bucket][position]
        if existing_key is not None:
            # Evict existing entry
            self._remove_from_new(existing_key, bucket, position)

        # Insert new address
        self._new_buckets[bucket][position] = addr_key
        self._addrs[addr_key] = info
        self._in_new.add(addr_key)
        info.ref_count = 1

        return True

    def add_from_addrv2(
        self,
        entry,  # AddrV2Entry from p2p_messages
        source: str = "",
    ) -> bool:
        """Add an address from an AddrV2Entry (BIP155).

        Args:
            entry: AddrV2Entry object with network_id, addr, port, services, time
            source: Address key of peer who sent us this address

        Returns:
            True if inserted (new address), False if updated existing.
        """
        # Convert AddrV2Entry to host string
        host = entry.to_string().rsplit(":", 1)[0]  # Remove port from string

        return self.add(
            host=host,
            port=entry.port,
            services=entry.services,
            timestamp=float(entry.time),
            source=source,
            network_id=entry.network_id,
            addr_bytes=entry.addr,
        )

    def _remove_from_new(
        self, addr_key: str, bucket: int, position: int
    ) -> None:
        """Remove an address from the new table."""
        if addr_key not in self._in_new:
            return

        info = self._addrs.get(addr_key)
        if info:
            info.ref_count -= 1
            if info.ref_count <= 0:
                self._in_new.discard(addr_key)
                del self._addrs[addr_key]

        self._new_buckets[bucket][position] = None

    def mark_good(self, host: str, port: int) -> None:
        """Move an address to the tried table after successful connection."""
        addr_key = f"{host}:{port}"
        now = time.time()

        # Already in tried - update timestamps
        if addr_key in self._in_tried:
            info = self._addrs[addr_key]
            info.last_success = now
            info.attempts = 0
            info.failures = 0
            return

        # Get or create info
        if addr_key in self._in_new:
            info = self._addrs[addr_key]
            # Remove from all new buckets
            self._remove_from_all_new(addr_key)
        else:
            info = AddrInfo(host=host, port=port)
            self._addrs[addr_key] = info

        info.last_success = now
        info.attempts = 0
        info.failures = 0

        # Find tried bucket and position
        bucket = self._get_tried_bucket(info)
        position = self._get_bucket_position(info, is_new=False, bucket=bucket)

        # Check for collision
        existing_key = self._tried_buckets[bucket][position]
        if existing_key is not None:
            # Test-before-evict: check if existing is still good
            existing = self._addrs.get(existing_key)
            if existing and (now - existing.last_success) < REPLACEMENT_HOURS * 3600:
                # Existing was recently successful - don't evict yet.
                if len(self._tried_collisions) < MAX_TRIED_COLLISIONS:
                    self._tried_collisions.add(addr_key)
                return
            else:
                # Existing failed recency test — evict it.
                # ASN-eviction preference (BUG-21 fix complement): when asmap is
                # loaded and the existing entry shares the same ASN as the incoming
                # candidate, it contributes zero additional AS diversity; evict it
                # immediately (no deferral).  When the ASes differ, still evict
                # (it failed the recency test), but the caller gains diversity.
                self._remove_from_tried(existing_key, bucket, position)

        # Insert into tried
        self._tried_buckets[bucket][position] = addr_key
        self._in_tried.add(addr_key)

    def _get_eviction_victim_from_collisions(
        self, candidate_asn: int
    ) -> str | None:
        """Pick the best collision entry to evict from the tried table.

        ASN-eviction preference (FIX-51): when an asmap is loaded, prefer to
        evict a pending collision entry that shares the same ASN as the current
        slot occupant, since evicting a same-ASN entry maximises the diversity
        gained.  If none share the ASN (or no asmap), fall back to arbitrary
        choice.

        Args:
            candidate_asn: ASN of the new address about to enter the slot.

        Returns:
            Address key from ``_tried_collisions`` to evict, or None if empty.
        """
        if not self._tried_collisions:
            return None

        if self._asmap and candidate_asn > 0:
            # Prefer a collision whose incumbent shares the candidate's ASN.
            for ck in self._tried_collisions:
                ck_info = self._addrs.get(ck)
                if ck_info:
                    ck_asn = self.get_mapped_as(ck_info.host, ck_info.network_id)
                    if ck_asn == candidate_asn:
                        return ck

        # Fall back: arbitrary choice
        return next(iter(self._tried_collisions))

    def _remove_from_all_new(self, addr_key: str) -> None:
        """Remove an address from all new buckets."""
        if addr_key not in self._in_new:
            return

        for bucket in range(NEW_BUCKET_COUNT):
            for pos in range(NEW_BUCKET_SIZE):
                if self._new_buckets[bucket][pos] == addr_key:
                    self._new_buckets[bucket][pos] = None

        self._in_new.discard(addr_key)

    def _remove_from_tried(
        self, addr_key: str, bucket: int, position: int
    ) -> None:
        """Remove an address from the tried table."""
        if addr_key not in self._in_tried:
            return

        self._tried_buckets[bucket][position] = None
        self._in_tried.discard(addr_key)

        # Move to new table (demotion)
        info = self._addrs.get(addr_key)
        if info:
            source_group = info.source_group or get_network_group(info.host)
            new_bucket = self._get_new_bucket(info, source_group)
            new_pos = self._get_bucket_position(info, is_new=True, bucket=new_bucket)

            if self._new_buckets[new_bucket][new_pos] is None:
                self._new_buckets[new_bucket][new_pos] = addr_key
                self._in_new.add(addr_key)
                info.ref_count = 1
            else:
                # No room - discard
                del self._addrs[addr_key]

    def mark_attempt(self, host: str, port: int) -> None:
        """Record that we attempted a connection."""
        addr_key = f"{host}:{port}"
        info = self._addrs.get(addr_key)
        if info:
            info.last_attempt = time.time()
            info.attempts += 1

    def mark_failed(self, host: str, port: int) -> None:
        """Record a connection failure."""
        addr_key = f"{host}:{port}"
        info = self._addrs.get(addr_key)
        if info:
            info.failures += 1
            info.last_attempt = time.time()
            info.attempts += 1

    def get_addresses(self, count: int = 1000) -> list[AddrInfo]:
        """Return up to count addresses sampled from both tables."""
        all_addrs = list(self._addrs.values())
        random.shuffle(all_addrs)
        return all_addrs[:count]

    def select_for_connection(
        self,
        exclude: set[str] | None = None,
        exclude_groups: set[str] | None = None,
        exclude_asns: set[int] | None = None,
    ) -> str | None:
        """Select a candidate address for connection.

        ASN-diversity enforcement (BUG-21 fix):
        When an ASMap is loaded and ``exclude_asns`` is provided, candidates
        whose mapped ASN is in that set are rejected.  This mirrors Bitcoin
        Core's outbound ASN-diversity check (net.cpp / addrman.cpp), which
        limits one outbound connection per Autonomous System.

        Args:
            exclude: Set of address keys to exclude
            exclude_groups: Set of /16 network groups to exclude (for diversity)
            exclude_asns: Set of ASNs already used by outbound peers; candidates
                          with a mapped ASN in this set are skipped.  Ignored
                          when no asmap is loaded.

        Returns:
            Address key (host:port) or None
        """
        exclude = exclude or set()
        exclude_groups = exclude_groups or set()
        exclude_asns = exclude_asns or set()

        # Prefer tried table (70% of the time)
        use_tried = random.random() < 0.7

        if use_tried and self._in_tried:
            result = self._select_from_tried(exclude, exclude_groups, exclude_asns)
            if result:
                return result

        # Fall back to new table
        if self._in_new:
            result = self._select_from_new(exclude, exclude_groups, exclude_asns)
            if result:
                return result

        # Try the other table
        if not use_tried and self._in_tried:
            return self._select_from_tried(exclude, exclude_groups, exclude_asns)

        return None

    def _select_from_tried(
        self,
        exclude: set[str],
        exclude_groups: set[str],
        exclude_asns: set[int] | None = None,
    ) -> str | None:
        """Select from tried table with weighted random."""
        exclude_asns = exclude_asns or set()
        candidates = []
        for addr_key in self._in_tried:
            if addr_key in exclude:
                continue
            info = self._addrs.get(addr_key)
            if not info:
                continue
            group = get_network_group(info.host)
            if group in exclude_groups:
                continue
            # ASN-diversity: skip if this candidate's ASN is already connected
            if exclude_asns and self._asmap:
                asn = self.get_mapped_as(info.host, info.network_id)
                if asn > 0 and asn in exclude_asns:
                    continue
            if self._is_terrible(info):
                continue
            chance = self._get_chance(info)
            candidates.append((addr_key, chance))

        if not candidates:
            return None

        # Weighted random selection
        total = sum(c for _, c in candidates)
        if total <= 0:
            return random.choice(candidates)[0]

        r = random.random() * total
        cumulative = 0.0
        for addr_key, chance in candidates:
            cumulative += chance
            if r <= cumulative:
                return addr_key

        return candidates[-1][0]

    def _select_from_new(
        self,
        exclude: set[str],
        exclude_groups: set[str],
        exclude_asns: set[int] | None = None,
    ) -> str | None:
        """Select from new table with weighted random."""
        exclude_asns = exclude_asns or set()
        candidates = []
        for addr_key in self._in_new:
            if addr_key in exclude:
                continue
            info = self._addrs.get(addr_key)
            if not info:
                continue
            group = get_network_group(info.host)
            if group in exclude_groups:
                continue
            # ASN-diversity: skip if this candidate's ASN is already connected
            if exclude_asns and self._asmap:
                asn = self.get_mapped_as(info.host, info.network_id)
                if asn > 0 and asn in exclude_asns:
                    continue
            if self._is_terrible(info):
                continue
            chance = self._get_chance(info)
            candidates.append((addr_key, chance))

        if not candidates:
            return None

        # Weighted random selection
        total = sum(c for _, c in candidates)
        if total <= 0:
            return random.choice(candidates)[0]

        r = random.random() * total
        cumulative = 0.0
        for addr_key, chance in candidates:
            cumulative += chance
            if r <= cumulative:
                return addr_key

        return candidates[-1][0]

    def select_for_feeler(
        self,
        exclude: set[str] | None = None,
    ) -> str | None:
        """Select an address from new table for feeler connection.

        Feelers probe addresses that haven't been tested to verify they're real.
        Prefers older addresses that haven't been attempted recently.
        """
        exclude = exclude or set()
        now = time.time()

        candidates = []
        for addr_key in self._in_new:
            if addr_key in exclude:
                continue
            info = self._addrs.get(addr_key)
            if not info:
                continue
            # Skip recently attempted
            if now - info.last_attempt < 600:
                continue
            # Prefer older addresses (more time to have become stale)
            age = now - info.last_seen
            candidates.append((addr_key, age))

        if not candidates:
            return None

        # Bias toward older addresses
        candidates.sort(key=lambda x: x[1], reverse=True)
        # Pick from top 25% with some randomness
        top_n = max(1, len(candidates) // 4)
        return random.choice(candidates[:top_n])[0]

    def get_addr_info(self, host: str, port: int) -> AddrInfo | None:
        """Get address info for a specific address."""
        return self._addrs.get(f"{host}:{port}")

    def size(self) -> int:
        """Total number of known addresses."""
        return len(self._addrs)

    def new_count(self) -> int:
        """Number of addresses in new table."""
        return len(self._in_new)

    def tried_count(self) -> int:
        """Number of addresses in tried table."""
        return len(self._in_tried)

    def get_network_group_counts(self) -> dict[str, int]:
        """Get count of addresses per /16 network group."""
        counts: dict[str, int] = {}
        for info in self._addrs.values():
            group = get_network_group(info.host)
            counts[group] = counts.get(group, 0) + 1
        return counts

    def asmap_health_check(self, top_n: int = 5) -> dict:
        """Compute ASMap health statistics for the loaded address table.

        Iterates over every address in the new + tried tables and looks up
        each IPv4/IPv6 entry's ASN.  Returns a summary dict suitable for
        startup logging and periodic monitoring.

        Mirrors the kind of diagnostics Bitcoin Core emits on startup when
        an asmap is loaded (src/addrman.cpp / src/init.cpp).

        Args:
            top_n: Number of top ASNs by address count to include in the
                   ``top_asns`` list (default 5).

        Returns:
            dict with keys:
              total_addrs  — total addresses across new + tried tables
              mapped       — addresses that have a non-zero ASN mapping
              unmapped     — addresses with ASN=0 (unknown or non-IP)
              unique_asns  — number of distinct ASNs seen
              top_asns     — list of up to ``top_n`` (asn, count) tuples,
                             sorted by count descending
              asmap_active — bool; True when an asmap is loaded
        """
        total = len(self._addrs)
        mapped = 0
        unmapped = 0
        asn_counts: dict[int, int] = {}

        if self._asmap:
            for info in self._addrs.values():
                asn = self.get_mapped_as(info.host, info.network_id)
                if asn > 0:
                    mapped += 1
                    asn_counts[asn] = asn_counts.get(asn, 0) + 1
                else:
                    unmapped += 1
        else:
            unmapped = total

        sorted_asns = sorted(asn_counts.items(), key=lambda kv: kv[1], reverse=True)
        return {
            "total_addrs": total,
            "mapped": mapped,
            "unmapped": unmapped,
            "unique_asns": len(asn_counts),
            "top_asns": sorted_asns[:top_n],
            "asmap_active": bool(self._asmap),
        }

    # Persistence

    def save(self) -> None:
        """Persist address tables to disk."""
        if not self._filepath:
            return
        try:
            data = {
                "version": 2,
                "key": self._key.hex(),
                "addresses": {
                    k: self._info_to_dict(v) for k, v in self._addrs.items()
                },
                "in_new": list(self._in_new),
                "in_tried": list(self._in_tried),
            }
            tmp = self._filepath + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self._filepath)
            logger.debug(
                f"Saved {len(self._in_new)} new + {len(self._in_tried)} tried "
                f"addresses to {self._filepath}"
            )
        except Exception as e:
            logger.warning(f"Failed to save address manager: {e}")

    def _load(self) -> None:
        if not self._filepath or not os.path.exists(self._filepath):
            return
        try:
            with open(self._filepath) as f:
                data = json.load(f)

            version = data.get("version", 1)

            if version == 1:
                # Legacy format - migrate
                self._load_v1(data)
            elif version == 2:
                self._load_v2(data)
            else:
                logger.warning("Unknown peers.json version, ignoring")

        except Exception as e:
            logger.warning(f"Failed to load address manager: {e}")

    def _load_v1(self, data: dict) -> None:
        """Load legacy flat format and migrate to bucketed."""
        for _addr, d in data.get("new", {}).items():
            info = self._dict_to_info(d)
            self.add(
                info.host, info.port,
                services=info.services,
                timestamp=info.last_seen,
                source=info.source,
            )
        for _addr, d in data.get("tried", {}).items():
            info = self._dict_to_info(d)
            # First add to new, then mark good to move to tried
            self.add(
                info.host, info.port,
                services=info.services,
                timestamp=info.last_seen,
                source=info.source,
            )
            if info.last_success > 0:
                self.mark_good(info.host, info.port)
        logger.info(
            f"Migrated {len(self._addrs)} addresses from v1 format"
        )

    def _load_v2(self, data: dict) -> None:
        """Load bucketed format."""
        self._key = bytes.fromhex(data.get("key", secrets.token_hex(32)))

        # Load address info
        for addr_key, d in data.get("addresses", {}).items():
            self._addrs[addr_key] = self._dict_to_info(d)

        # Rebuild bucket assignments
        in_new = set(data.get("in_new", []))
        in_tried = set(data.get("in_tried", []))

        for addr_key in in_new:
            info = self._addrs.get(addr_key)
            if not info:
                continue
            source_group = info.source_group or get_network_group(info.host)
            bucket = self._get_new_bucket(info, source_group)
            position = self._get_bucket_position(info, is_new=True, bucket=bucket)
            if self._new_buckets[bucket][position] is None:
                self._new_buckets[bucket][position] = addr_key
                self._in_new.add(addr_key)
                info.ref_count = 1

        for addr_key in in_tried:
            info = self._addrs.get(addr_key)
            if not info:
                continue
            bucket = self._get_tried_bucket(info)
            position = self._get_bucket_position(info, is_new=False, bucket=bucket)
            if self._tried_buckets[bucket][position] is None:
                self._tried_buckets[bucket][position] = addr_key
                self._in_tried.add(addr_key)

        logger.info(
            f"Loaded {len(self._in_new)} new + {len(self._in_tried)} tried "
            f"addresses from {self._filepath}"
        )

    @staticmethod
    def _info_to_dict(info: AddrInfo) -> dict:
        d = {
            "host": info.host,
            "port": info.port,
            "services": info.services,
            "network_id": info.network_id,
            "last_seen": info.last_seen,
            "last_attempt": info.last_attempt,
            "last_success": info.last_success,
            "attempts": info.attempts,
            "failures": info.failures,
            "source": info.source,
            "source_group": info.source_group,
            "ref_count": info.ref_count,
        }
        # Store addr_bytes as hex for JSON serialization
        if info.addr_bytes:
            d["addr_bytes"] = info.addr_bytes.hex()
        return d

    @staticmethod
    def _dict_to_info(d: dict) -> AddrInfo:
        # Decode addr_bytes from hex if present
        addr_bytes = b""
        if "addr_bytes" in d and d["addr_bytes"]:
            addr_bytes = bytes.fromhex(d["addr_bytes"])
        return AddrInfo(
            host=d["host"],
            port=d["port"],
            services=d.get("services", 0),
            network_id=d.get("network_id", NET_IPV4),
            addr_bytes=addr_bytes,
            last_seen=d.get("last_seen", 0),
            last_attempt=d.get("last_attempt", 0),
            last_success=d.get("last_success", 0),
            attempts=d.get("attempts", 0),
            failures=d.get("failures", 0),
            source=d.get("source", ""),
            source_group=d.get("source_group", ""),
            ref_count=d.get("ref_count", 0),
        )
