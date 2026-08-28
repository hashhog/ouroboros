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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

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
SCORE_UNREQUESTED_DATA = 5       # Unrequested block/tx data
SCORE_ORPHAN_TX = 1              # Orphan transaction (low score, not misbehavior)
SCORE_HEADERS_NOT_CONNECT = 20   # Headers don't connect to our chain
SCORE_BLOCK_DOWNLOAD_STALL = 50  # Stalling block download
SCORE_INVALID_MESSAGE = 10       # Malformed P2P message
SCORE_ADDR_SPAM = 5              # Excessive addr relay

# Legacy aliases
SCORE_INVALID_BLOCK_HEADER = SCORE_INVALID_HEADERS
SCORE_INVALID_TX_HIGH = SCORE_INVALID_TX
SCORE_INVALID_TX_LOW = 1
SCORE_UNSOLICITED_BLOCK = SCORE_UNREQUESTED_DATA

# Retention bounds for the misbehaviour-score table.  Without these the
# ``scores`` dict grows one entry per unique below-threshold misbehaving IP
# (and each record's ``events`` list grows one string per event) with no
# expiry — a slow unbounded leak under inbound churn from peers that
# reconnect under new ephemeral ports.  A score record whose last event is
# older than ``SCORE_RECORD_TTL`` is reclaimed by ``sweep_expired``; each
# record's ``events`` is capped to the most recent ``SCORE_EVENTS_MAX``.
# Mirrors the spirit of Core's DEFAULT_MISBEHAVING_BANTIME (24 h).
SCORE_RECORD_TTL = 86400.0  # seconds (24 h)
SCORE_EVENTS_MAX = 20


@dataclass
class MisbehaviorRecord:
    """Running misbehavior state for a single IP."""
    score: int = 0
    events: list[str] = field(default_factory=list)
    last_event: float = 0.0


class BanManager:
    """Track peer misbehavior and enforce time-limited bans.

    Single-event discourage model (Bitcoin Core 2022, PR #25974):
    Any misbehavior event whose individual score meets or exceeds
    ``discouragement_threshold`` immediately triggers a ban/discourage,
    regardless of the cumulative score.  This mirrors Core's
    MaybeDiscourageAndDisconnect where a single Misbehaving() call sets
    m_should_discourage=True and disconnects on the next loop iteration.

    Low-severity events (score < discouragement_threshold) still accumulate
    and trigger a ban only when the cumulative total reaches ``ban_threshold``.
    """

    # Per-event threshold: a single event with score >= this value triggers
    # an immediate discourage/ban even if the cumulative score is below
    # ban_threshold.  Matches the spirit of Core 2022 PR #25974 where any
    # Misbehaving() call sets should_discourage=True.
    DISCOURAGEMENT_THRESHOLD: int = 50

    def __init__(
        self,
        ban_threshold: int = 100,
        ban_duration: int = 86400,
        data_dir: str | None = None,
        on_ban: Callable[[str], None] | None = None,
    ):
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self._data_dir = data_dir
        self._on_ban = on_ban

        self.scores: dict[str, MisbehaviorRecord] = {}
        self.banned: dict[str, float] = {}  # ip -> ban_until (epoch)

        if data_dir:
            self._load_bans()

    # Public API

    def record_misbehavior(self, ip: str, score: int, reason: str) -> bool:
        """Add *score* points for *ip*.  Ban if single-event or cumulative threshold reached.

        Bitcoin Core 2022 (PR #25974) single-event discourage model:
        if a single event score >= DISCOURAGEMENT_THRESHOLD the peer is
        banned immediately (should_discourage=True), regardless of prior
        cumulative score.  Cumulative ban still applies when total reaches
        ban_threshold.

        Returns True if the peer was banned as a result of this call.
        """
        rec = self.scores.setdefault(ip, MisbehaviorRecord())
        rec.score += score
        rec.events.append(reason)
        # Cap the per-record events ring so a single long-lived misbehaving
        # IP cannot accrete an unbounded list of reason strings.
        if len(rec.events) > SCORE_EVENTS_MAX:
            del rec.events[:-SCORE_EVENTS_MAX]
        rec.last_event = time.time()

        logger.debug(
            "Misbehavior: %s  +%d (%s)  total=%d",
            ip, score, reason, rec.score,
        )

        # Single-event discourage: any event with score >= DISCOURAGEMENT_THRESHOLD
        # triggers an immediate ban, mirroring Core's MaybeDiscourageAndDisconnect
        # where a single Misbehaving() call sets m_should_discourage=True.
        if score >= self.DISCOURAGEMENT_THRESHOLD or rec.score >= self.ban_threshold:
            # Propagate WHY.  The event that tripped the threshold is the only
            # thing that makes a ban actionable, and it was previously visible
            # only at DEBUG.
            trigger = ("single-event" if score >= self.DISCOURAGEMENT_THRESHOLD
                       else "cumulative")
            self.ban(ip, reason=f"{reason} (score +{score} -> {rec.score}, {trigger})")
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

    def ban(self, ip: str, duration: int | None = None,
            reason: str | None = None) -> None:
        """Immediately ban *ip* for *duration* seconds (default: ban_duration).

        *reason* is REQUIRED in spirit even though it defaults to None for
        backwards compatibility with existing call sites: without it a ban is
        unattributable in production.  record_misbehavior logs the triggering
        reason at DEBUG, and the daemons run at INFO, so before this parameter
        existed an operator saw only "Banned <ip> for 86400 s" with no cause.
        On 2026-08-28 ouroboros emitted 413 such lines in three hours during a
        live stall and NONE of them could be attributed to anything.
        """
        ban_time = duration if duration is not None else self.ban_duration
        self.banned[ip] = time.time() + ban_time
        self.scores.pop(ip, None)
        if reason:
            logger.warning("Banned %s for %d s: %s", ip, ban_time, reason)
        else:
            logger.warning("Banned %s for %d s: <no reason supplied by caller>",
                           ip, ban_time)

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
            self.ban(ip, duration=duration, reason="setban RPC")
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

    def list_banned(self) -> dict[str, float]:
        """Return a snapshot of currently-banned IPs and their expiry."""
        now = time.time()
        self.banned = {ip: t for ip, t in self.banned.items() if t > now}
        return dict(self.banned)

    def list_banned_detailed(self) -> list[dict[str, any]]:
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
        """Remove expired bans + stale score records; return how many bans were removed.

        Prunes two structures:
          - ``banned``: drop entries whose ban window has elapsed (as before).
          - ``scores``: drop misbehaviour-score records whose last event is
            older than ``SCORE_RECORD_TTL``.  Without this the score table
            grew one entry per unique below-threshold misbehaving IP forever
            (it is never cleared on disconnect) — a slow unbounded leak under
            inbound churn.  A genuine repeat-offender re-arms its record on the
            next event, so reclaiming an idle one is harmless.

        Must be driven by a periodic caller (the PeerManager maintenance loop
        wires this in); it had none before, so neither structure self-pruned.

        Returns the number of *bans* removed (unchanged from the prior
        contract; the score reclaim is incidental hygiene).
        """
        now = time.time()
        expired = [ip for ip, t in self.banned.items() if t <= now]
        for ip in expired:
            del self.banned[ip]
        if expired and self._data_dir:
            self._save_bans()

        # Reclaim idle below-threshold score records.
        stale_scores = [
            ip for ip, rec in self.scores.items()
            if now - rec.last_event > SCORE_RECORD_TTL
        ]
        for ip in stale_scores:
            del self.scores[ip]
        if stale_scores:
            logger.debug("Swept %d stale misbehaviour-score record(s)",
                         len(stale_scores))

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
