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
        """Unique key for this address."""
        return f"{self.host}:{self.port}"

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


def _hash_for_bucket(key: bytes, *args) -> int:
    """Compute hash for bucket assignment using SHA256."""
    h = hashlib.sha256(key)
    for arg in args:
        if isinstance(arg, str):
            h.update(arg.encode())
        elif isinstance(arg, bytes):
            h.update(arg)
        elif isinstance(arg, int):
            h.update(arg.to_bytes(8, "little"))
    return int.from_bytes(h.digest()[:8], "little")


class AddressManager:
    """Manages known peer addresses with bucketed new/tried tables.

    Eclipse attack mitigations:
    - Deterministic bucket assignment prevents manipulation
    - Source group tracking limits single-source influence
    - Network group diversification spreads across /16 ranges
    """

    def __init__(self, data_dir: str | None = None):
        # Secret key for deterministic bucket hashing (anti-manipulation)
        self._key: bytes = secrets.token_bytes(32)

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

    # Bucket computation

    def _get_new_bucket(self, addr: AddrInfo, source_group: str) -> int:
        """Compute new table bucket for an address.

        bucket = hash(key, addr_group, source_group) % 64
                 then hash(key, source_group, bucket) % 256
        """
        addr_group = get_network_group(addr.host, addr.network_id)
        hash1 = _hash_for_bucket(
            self._key, addr_group, source_group
        )
        hash2 = _hash_for_bucket(
            self._key, source_group, hash1 % NEW_BUCKETS_PER_SOURCE_GROUP
        )
        return hash2 % NEW_BUCKET_COUNT

    def _get_tried_bucket(self, addr: AddrInfo) -> int:
        """Compute tried table bucket for an address.

        bucket = hash(key, addr_group, hash(key, addr_key) % 8) % 64
        """
        addr_key = addr.get_key()
        addr_group = get_network_group(addr.host, addr.network_id)
        hash1 = _hash_for_bucket(self._key, addr_key)
        hash2 = _hash_for_bucket(
            self._key, addr_group, hash1 % TRIED_BUCKETS_PER_GROUP
        )
        return hash2 % TRIED_BUCKET_COUNT

    def _get_bucket_position(
        self, addr: AddrInfo, is_new: bool, bucket: int
    ) -> int:
        """Compute position within a bucket."""
        prefix = b"N" if is_new else b"K"
        hash_val = _hash_for_bucket(
            self._key, prefix, bucket, addr.get_key()
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
                # Existing was recently successful - don't evict yet
                if len(self._tried_collisions) < MAX_TRIED_COLLISIONS:
                    self._tried_collisions.add(addr_key)
                return
            else:
                # Evict existing
                self._remove_from_tried(existing_key, bucket, position)

        # Insert into tried
        self._tried_buckets[bucket][position] = addr_key
        self._in_tried.add(addr_key)

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
    ) -> str | None:
        """Select a candidate address for connection.

        Args:
            exclude: Set of address keys to exclude
            exclude_groups: Set of /16 network groups to exclude (for diversity)

        Returns:
            Address key (host:port) or None
        """
        exclude = exclude or set()
        exclude_groups = exclude_groups or set()

        # Prefer tried table (70% of the time)
        use_tried = random.random() < 0.7

        if use_tried and self._in_tried:
            result = self._select_from_tried(exclude, exclude_groups)
            if result:
                return result

        # Fall back to new table
        if self._in_new:
            result = self._select_from_new(exclude, exclude_groups)
            if result:
                return result

        # Try the other table
        if not use_tried and self._in_tried:
            return self._select_from_tried(exclude, exclude_groups)

        return None

    def _select_from_tried(
        self,
        exclude: set[str],
        exclude_groups: set[str],
    ) -> str | None:
        """Select from tried table with weighted random."""
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
    ) -> str | None:
        """Select from new table with weighted random."""
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
