"""
Address manager for peer discovery and gossip.

Maintains two tables of known peer addresses:
  - **new**: addresses learned from DNS seeds or ``addr``/``addrv2``
    messages that have not yet been successfully connected.
  - **tried**: addresses that we have connected to at least once.

Persists to ``{datadir}/peers.json`` so addresses survive restarts.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

MAX_ADDRESSES = 65_536
MAX_NEW = 49_152      # ~75 % for new
MAX_TRIED = 16_384    # ~25 % for tried


@dataclass
class AddrInfo:
    """Metadata for a single peer address."""

    host: str
    port: int
    services: int = 0
    last_seen: float = 0.0       # epoch — most recent addr timestamp
    last_attempt: float = 0.0    # epoch — when we last tried to connect
    last_success: float = 0.0    # epoch — when we last connected successfully
    attempts: int = 0
    source: str = ""             # who told us about this address


class AddressManager:
    """Manages known peer addresses with new/tried tables."""

    def __init__(self, data_dir: Optional[str] = None):
        self._new: Dict[str, AddrInfo] = {}     # addr -> AddrInfo
        self._tried: Dict[str, AddrInfo] = dict()   # addr -> AddrInfo
        self._data_dir = data_dir
        self._filepath: Optional[str] = None
        if data_dir:
            self._filepath = os.path.join(data_dir, "peers.json")
            self._load()

    # Public API #

    def add(
        self,
        host: str,
        port: int,
        services: int = 0,
        timestamp: float = 0.0,
        source: str = "",
    ) -> bool:
        """Add an address to the *new* table; returns True if inserted/updated."""
        addr = f"{host}:{port}"

        # Already in tried — just update last_seen
        if addr in self._tried:
            if timestamp > self._tried[addr].last_seen:
                self._tried[addr].last_seen = timestamp
            return False

        if addr in self._new:
            info = self._new[addr]
            if timestamp > info.last_seen:
                info.last_seen = timestamp
            if services:
                info.services = services
            return False

        # Evict a random entry if full
        if len(self._new) >= MAX_NEW:
            evict_key = random.choice(list(self._new))
            del self._new[evict_key]

        self._new[addr] = AddrInfo(
            host=host,
            port=port,
            services=services,
            last_seen=timestamp or time.time(),
            source=source,
        )
        return True

    def mark_good(self, host: str, port: int) -> None:
        """Move an address to the *tried* table after a successful connection."""
        addr = f"{host}:{port}"
        now = time.time()

        if addr in self._tried:
            self._tried[addr].last_success = now
            self._tried[addr].attempts = 0
            return

        info = self._new.pop(addr, None)
        if info is None:
            info = AddrInfo(host=host, port=port)

        info.last_success = now
        info.attempts = 0

        # Evict from tried if full
        if len(self._tried) >= MAX_TRIED:
            evict_key = random.choice(list(self._tried))
            # Demote evicted entry back to new
            evicted = self._tried.pop(evict_key)
            if len(self._new) < MAX_NEW:
                self._new[evict_key] = evicted

        self._tried[addr] = info

    def mark_attempt(self, host: str, port: int) -> None:
        """Record that we attempted (and possibly failed) a connection."""
        addr = f"{host}:{port}"
        now = time.time()
        for table in (self._new, self._tried):
            if addr in table:
                table[addr].last_attempt = now
                table[addr].attempts += 1
                return

    def get_addresses(self, count: int = 1000) -> List[AddrInfo]:
        """Return up to *count* addresses sampled from both tables."""
        all_addrs = list(self._new.values()) + list(self._tried.values())
        random.shuffle(all_addrs)
        return all_addrs[:count]

    def select_for_connection(self, exclude: Set[str] | None = None) -> Optional[str]:
        """Pick a candidate from the *new* table, weighting by recency and low attempt count."""
        exclude = exclude or set()
        candidates = [
            (addr, info) for addr, info in self._new.items()
            if addr not in exclude
        ]
        if not candidates:
            return None

        # Weight: prefer fewer attempts and more recent last_seen
        now = time.time()
        weighted: list[tuple[float, str]] = []
        for addr, info in candidates:
            age = max(now - info.last_seen, 1)
            weight = 1.0 / (1 + info.attempts) / (1 + age / 86400)
            weighted.append((weight, addr))

        # Weighted random selection
        total = sum(w for w, _ in weighted)
        if total <= 0:
            return random.choice([a for _, a in weighted])

        r = random.random() * total
        cumulative = 0.0
        for weight, addr in weighted:
            cumulative += weight
            if r <= cumulative:
                return addr
        return weighted[-1][1]

    def size(self) -> int:
        """Total number of known addresses."""
        return len(self._new) + len(self._tried)

    # Persistence

    def save(self) -> None:
        """Persist address tables to disk."""
        if not self._filepath:
            return
        try:
            data = {
                "version": 1,
                "new": {k: self._info_to_dict(v) for k, v in self._new.items()},
                "tried": {k: self._info_to_dict(v) for k, v in self._tried.items()},
            }
            tmp = self._filepath + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self._filepath)
            logger.debug(
                f"Saved {len(self._new)} new + {len(self._tried)} tried "
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
            if data.get("version") != 1:
                logger.warning("Unknown peers.json version, ignoring")
                return
            for addr, d in data.get("new", {}).items():
                self._new[addr] = self._dict_to_info(d)
            for addr, d in data.get("tried", {}).items():
                self._tried[addr] = self._dict_to_info(d)
            logger.info(
                f"Loaded {len(self._new)} new + {len(self._tried)} tried "
                f"addresses from {self._filepath}"
            )
        except Exception as e:
            logger.warning(f"Failed to load address manager: {e}")

    @staticmethod
    def _info_to_dict(info: AddrInfo) -> dict:
        return {
            "host": info.host,
            "port": info.port,
            "services": info.services,
            "last_seen": info.last_seen,
            "last_attempt": info.last_attempt,
            "last_success": info.last_success,
            "attempts": info.attempts,
            "source": info.source,
        }

    @staticmethod
    def _dict_to_info(d: dict) -> AddrInfo:
        return AddrInfo(
            host=d["host"],
            port=d["port"],
            services=d.get("services", 0),
            last_seen=d.get("last_seen", 0),
            last_attempt=d.get("last_attempt", 0),
            last_success=d.get("last_success", 0),
            attempts=d.get("attempts", 0),
            source=d.get("source", ""),
        )
