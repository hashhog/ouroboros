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

# ── Misbehavior score table (following Bitcoin Core) ─────────────────

SCORE_INVALID_BLOCK_HEADER = 100
SCORE_INVALID_BLOCK = 100
SCORE_INVALID_TX_HIGH = 10
SCORE_INVALID_TX_LOW = 1
SCORE_ORPHAN_TX = 1
SCORE_UNSOLICITED_BLOCK = 20
SCORE_HEADERS_NOT_CONNECT = 10
SCORE_INVALID_MESSAGE = 10
SCORE_ADDR_SPAM = 5


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
        """
        Args:
            ban_threshold: Cumulative score that triggers a ban.
            ban_duration:  Ban length in seconds (default 24 h).
            data_dir:      If set, persist bans to ``<data_dir>/bans.json``.
            on_ban:        Optional callback invoked with the IP when a ban
                           is triggered (used by PeerManager to disconnect).
        """
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self._data_dir = data_dir
        self._on_ban = on_ban

        self.scores: Dict[str, MisbehaviorRecord] = {}
        self.banned: Dict[str, float] = {}  # ip -> ban_until (epoch)

        if data_dir:
            self._load_bans()

    # ── Public API ──────────────────────────────────────────────────

    def record_misbehavior(self, ip: str, score: int, reason: str) -> None:
        """Add *score* points for *ip*.  Ban if threshold is reached."""
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

    def ban(self, ip: str) -> None:
        """Immediately ban *ip* for ``ban_duration`` seconds."""
        self.banned[ip] = time.time() + self.ban_duration
        self.scores.pop(ip, None)
        logger.warning("Banned %s for %d s", ip, self.ban_duration)

        if self._data_dir:
            self._save_bans()
        if self._on_ban:
            self._on_ban(ip)

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

    def sweep_expired(self) -> int:
        """Remove expired bans.  Returns count of bans removed."""
        now = time.time()
        expired = [ip for ip, t in self.banned.items() if t <= now]
        for ip in expired:
            del self.banned[ip]
        if expired and self._data_dir:
            self._save_bans()
        return len(expired)

    # ── Persistence ─────────────────────────────────────────────────

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
