"""
Peer misbehavior tracking and ban management.

Scores misbehavior events per-IP and automatically bans peers whose
cumulative score reaches a configurable threshold.  Bans expire after
a configurable duration (default 24 h).

Reference: bitcoin/src/banman.cpp, bitcoin/src/net_processing.cpp (Misbehaving())
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Misbehavior score table
# Reference: Bitcoin Core net_processing.cpp Misbehaving() calls
# ---------------------------------------------------------------------------

# Instant bans (score >= 100)
SCORE_INVALID_BLOCK = 100        # Invalid block (consensus failure)
SCORE_INVALID_HEADERS = 20       # Invalid headers (e.g., bad PoW, doesn't connect)
SCORE_INVALID_TX = 10            # Invalid transaction

# Other violations
SCORE_UNREQUESTED_DATA = 20      # Unrequested block/tx data
SCORE_ORPHAN_TX = 1              # Orphan transaction (low score, not misbehavior)
SCORE_HEADERS_NOT_CONNECT = 10   # Headers don't connect to our chain
SCORE_INVALID_MESSAGE = 10       # Malformed P2P message
SCORE_ADDR_SPAM = 5              # Excessive addr relay

# Legacy aliases
SCORE_INVALID_BLOCK_HEADER = SCORE_INVALID_HEADERS
SCORE_INVALID_TX_HIGH = SCORE_INVALID_TX
SCORE_INVALID_TX_LOW = 1
SCORE_UNSOLICITED_BLOCK = SCORE_UNREQUESTED_DATA


@dataclass
class MisbehaviorRecord:
    """Running misbehavior state for a single IP."""
    score: int = 0
    events: List[str] = field(default_factory=list)
    last_event: float = 0.0


class BanManager:
    """Track peer misbehavior and enforce time-limited bans."""

    def __init__(
        self,
        ban_threshold: int = 100,
        ban_duration: int = 86400,
        data_dir: Optional[str] = None,
        on_ban: Optional[Callable[[str], None]] = None,
    ):
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self._data_dir = data_dir
        self._on_ban = on_ban

        self.scores: Dict[str, MisbehaviorRecord] = {}
        self.banned: Dict[str, float] = {}  # ip -> ban_until (epoch)

        if data_dir:
            self._load_bans()

    # Public API

    def record_misbehavior(self, ip: str, score: int, reason: str) -> bool:
        """Add *score* points for *ip*.  Ban if threshold is reached.

        Returns True if the peer was banned as a result of this call.
        """
        rec = self.scores.setdefault(ip, MisbehaviorRecord())
        rec.score += score
        rec.events.append(reason)
        rec.last_event = time.time()

        logger.debug(
            "Misbehavior: %s  +%d (%s)  total=%d",
            ip, score, reason, rec.score,
        )

        if rec.score >= self.ban_threshold:
            self.ban(ip)
            return True
        return False

    def misbehaving(self, peer_id: str, score: int, reason: str) -> bool:
        """Record misbehavior for a peer (Bitcoin Core API compatibility).

        This is an alias for record_misbehavior() that matches the naming
        convention used in Bitcoin Core's net_processing.cpp.

        Args:
            peer_id: Peer identifier (IP address or IP:port)
            score: Misbehavior score to add
            reason: Human-readable reason for the misbehavior

        Returns:
            True if the peer was banned as a result
        """
        return self.record_misbehavior(peer_id, score, reason)

    def ban(self, ip: str, duration: Optional[int] = None) -> None:
        """Immediately ban *ip* for *duration* seconds (default: ban_duration)."""
        ban_time = duration if duration is not None else self.ban_duration
        self.banned[ip] = time.time() + ban_time
        self.scores.pop(ip, None)
        logger.warning("Banned %s for %d s", ip, ban_time)

        if self._data_dir:
            self._save_bans()
        if self._on_ban:
            self._on_ban(ip)

    def setban(
        self,
        ip: str,
        command: str = "add",
        bantime: int = 0,
        absolute: bool = False,
    ) -> bool:
        """Set or remove a ban (Bitcoin Core RPC compatibility).

        Args:
            ip: IP address or subnet to ban
            command: "add" to ban, "remove" to unban
            bantime: Ban duration in seconds (0 = use default 24h)
            absolute: If True, bantime is an absolute UNIX timestamp

        Returns:
            True if operation succeeded
        """
        if command == "add":
            if bantime == 0:
                duration = self.ban_duration
            elif absolute:
                # bantime is an absolute timestamp
                duration = max(0, int(bantime - time.time()))
            else:
                duration = bantime
            self.ban(ip, duration=duration)
            return True
        elif command == "remove":
            self.unban(ip)
            return True
        else:
            logger.warning("Unknown setban command: %s", command)
            return False

    def is_banned(self, ip: str) -> bool:
        """Return True if *ip* is currently banned."""
        if ip not in self.banned:
            return False
        if time.time() > self.banned[ip]:
            del self.banned[ip]
            if self._data_dir:
                self._save_bans()
            return False
        return True

    def unban(self, ip: str) -> None:
        """Manually remove a ban."""
        if ip in self.banned:
            del self.banned[ip]
            logger.info("Unbanned %s", ip)
            if self._data_dir:
                self._save_bans()

    def clear_score(self, ip: str) -> None:
        """Reset misbehavior score for *ip* (e.g. after successful block)."""
        self.scores.pop(ip, None)

    def get_score(self, ip: str) -> int:
        rec = self.scores.get(ip)
        return rec.score if rec else 0

    def list_banned(self) -> Dict[str, float]:
        """Return a snapshot of currently-banned IPs and their expiry."""
        now = time.time()
        self.banned = {ip: t for ip, t in self.banned.items() if t > now}
        return dict(self.banned)

    def list_banned_detailed(self) -> List[Dict[str, any]]:
        """Return detailed ban info for each banned IP (for listbanned RPC).

        Returns a list of dicts with:
            - address: The banned IP/subnet
            - ban_created: UNIX timestamp when ban was created
            - banned_until: UNIX timestamp when ban expires
            - ban_duration: Duration in seconds
        """
        now = time.time()
        result = []
        for ip, ban_until in list(self.banned.items()):
            if ban_until <= now:
                continue
            # We don't store ban_created, so estimate it from ban_until
            # This is an approximation; ideally we'd store creation time
            duration = int(ban_until - now)
            result.append({
                "address": ip,
                "ban_created": int(ban_until - self.ban_duration),
                "banned_until": int(ban_until),
                "ban_duration": duration,
            })
        return result

    def sweep_expired(self) -> int:
        """Remove expired bans and return how many were removed."""
        now = time.time()
        expired = [ip for ip, t in self.banned.items() if t <= now]
        for ip in expired:
            del self.banned[ip]
        if expired and self._data_dir:
            self._save_bans()
        return len(expired)

    # --- Persistence ---

    def _bans_path(self) -> Path:
        return Path(self._data_dir) / "bans.json"

    def _save_bans(self) -> None:
        try:
            self._bans_path().write_text(
                json.dumps(self.banned), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to save bans: %s", exc)

    def _load_bans(self) -> None:
        path = self._bans_path()
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            now = time.time()
            self.banned = {ip: t for ip, t in raw.items() if t > now}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load bans: %s", exc)
