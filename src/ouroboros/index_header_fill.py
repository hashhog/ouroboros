"""Online backfill of the header into header-less block-index entries.

WHY THIS EXISTS
---------------
Bitcoin Core answers ``getblockheader`` for every entry of its block index: a
``CBlockIndex`` always holds the header fields (chain.h), because a block
enters the index only through ``AcceptBlockHeader`` -> ``AddToBlockIndex``
with its header in hand.

ouroboros' hash index (``BLOCK_INDEX_BY_HASH_CF``) gained the 80-byte header in
the v2 encoding (ouroboros#146), and the v2 migration upgraded every entry for
which a store held the header.  It could not upgrade the rows the assumeUTXO
header backfill (#52, ``header_backfill.py``) wrote below the snapshot base:
that backfill verified the headers and then stored only height, chainwork and
time.  After the 2026-11-16 mainnet deploy 711,249 entries were left like that,
and ``getblockheader`` answered "Block not found" at heights such as 500000
while ``getblockhash`` answered the same heights with Core's hashes.

WHAT IT DOES
------------
Two resumable passes, each a series of small steps run under the chain lock
(so no connect, invalidate or reorg rewrites an entry while a step does):

1. **Active chain, in height order** (``fill_index_headers_by_height``).  For
   each header-less entry, a local header (HEADERS_CF, or the stored body when
   it parses and matches its merkle root) is written if it hashes to the
   entry's key and links to the entry one height below.  A run of entries with
   no local header is fetched with one ``getheaders`` (locator = the hash one
   below the run) and the reply goes through ``attach_index_headers``, which
   applies the same two checks.  The resume height is written in the same
   RocksDB batch as the entries, so a kill resumes where the last step ended.
2. **Every key** (``fill_index_headers_by_hash``), once: reaches the entries
   that are not on the active chain (side branches, invalidated blocks).  Only
   local headers are used there; a peer cannot be asked for a stale branch by
   locator.

Nothing ever changes an entry's 44 metadata bytes (height, chainwork, time,
status) and nothing is deleted, so the build before this one reads a filled
datadir unchanged (``BlockMetadata::from_bytes`` reads the first 44 bytes; the
v2 rollback proof, hashhog ``ouroboros-block-index-v2-deploy-plan``, §6).  A
header that fails a check is counted (``hash_mismatch``, ``corrupt_body``,
``unlinked``, ``unknown``) and logged, never written.

Trust: a header is attached only when its sha256d equals a block hash the
index already holds, which is the strongest check there is (a second preimage
of sha256d).  A peer cannot make the fill write anything else.

``tools/index_header_fill_dryrun.py`` runs both passes with ``write=False``
on a RocksDB secondary, so the counts can be taken on a live datadir first.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from typing import Any, Sequence

logger = logging.getLogger(__name__)

# Heights visited per by-height step / keys per by-key step.  Each visit is one
# or two point reads; a body is parsed only when the entry has no HEADERS_CF
# header, and the time budget bounds that.
STEP_MAX_SCAN = 2000
# Wall-clock budget per step inside the chain lock, milliseconds.
STEP_BUDGET_MS = 50
# Core MAX_HEADERS_RESULTS: a getheaders reply holds at most 2000 headers.
MAX_PEER_RUN = 2000
# Core HEADERS_RESPONSE_TIME (net_processing.cpp): a sent getheaders counts as
# in flight this long before the same request goes to another peer.
RESPONSE_TIME = 120.0

COUNT_KEYS = (
    "from_headers", "from_body", "attached", "already_v2", "need_peer",
    "hash_mismatch", "corrupt_body", "unlinked", "unknown", "no_source",
    "malformed", "no_entry",
)


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def enabled() -> bool:
    """``OUROBOROS_INDEX_HEADER_FILL=0`` turns the online fill off."""
    return os.environ.get("OUROBOROS_INDEX_HEADER_FILL", "1") != "0"


def supported(raw_db: Any) -> bool:
    """True when the compiled extension has the fill API (this build or later)."""
    return all(
        callable(getattr(raw_db, name, None))
        for name in ("fill_index_headers_by_height", "fill_index_headers_by_hash",
                     "attach_index_headers", "index_header_fill_cursor")
    )


class IndexHeaderFill:
    """Drives the two passes.  Transport-free: the caller sends the
    ``getheaders`` built from :meth:`locator` and hands replies to
    :meth:`accept`; tests feed headers directly."""

    def __init__(self, raw_db: Any, *, max_scan: int = STEP_MAX_SCAN,
                 budget_ms: int = STEP_BUDGET_MS, max_peer_run: int = MAX_PEER_RUN):
        self.db = raw_db
        self.max_scan = int(max_scan)
        self.budget_ms = int(budget_ms)
        self.max_peer_run = int(max_peer_run)
        height, key, key_done = raw_db.index_header_fill_cursor()
        self.next_height: int = int(height) if height is not None else 0
        self.next_key: bytes | None = bytes(key) if key is not None else None
        self.key_done: bool = bool(key_done)
        self.height_done = False
        # The run of consecutive active-chain heights waiting on a peer.
        self.peer_run: list[tuple[int, bytes]] = []
        self.counts: dict[str, int] = {k: 0 for k in COUNT_KEYS}
        self.req_locator: list[bytes] | None = None
        self.req_time = 0.0
        self.req_peer: Any = None
        self.started = time.time()
        self._logged_done = False

    # -- state ---------------------------------------------------------------

    def is_complete(self) -> bool:
        return self.height_done and not self.peer_run and self.key_done

    def waiting_on_peer(self) -> bool:
        return bool(self.peer_run)

    def _add(self, counts: dict) -> None:
        for k, v in counts.items():
            if k in self.counts:
                self.counts[k] += int(v)

    # -- local steps ---------------------------------------------------------

    def step(self) -> dict:
        """One bounded local step (blocking; run it in a thread under the
        chain lock).  Does nothing while a peer run is outstanding."""
        if self.peer_run:
            return {}
        if not self.height_done:
            counts, nxt, done, run = self.db.fill_index_headers_by_height(
                self.next_height, self.max_scan, self.budget_ms, self.max_peer_run, True,
            )
            self.next_height = int(nxt)
            self.peer_run = [(int(h), bytes(k)) for h, k in run]
            # The walk reached the tip; new blocks are connected with their
            # header (hash_index_value), so it does not need to follow the tip.
            self.height_done = bool(done) and not self.peer_run
            self._add(counts)
            self._log_refusals(counts, "active chain")
            return counts
        if not self.key_done:
            counts, nxt, done = self.db.fill_index_headers_by_hash(
                self.next_key, self.max_scan, self.budget_ms, True,
            )
            self.next_key = bytes(nxt) if nxt is not None else self.next_key
            self.key_done = bool(done)
            # need_peer here means an active-chain entry the by-height pass
            # serves; already_v2 is the bulk of the index.  Count neither.
            self._add({k: v for k, v in counts.items()
                       if k not in ("need_peer", "already_v2")})
            self._log_refusals(counts, "all keys")
            return counts
        return {}

    def _log_refusals(self, counts: dict, where: str) -> None:
        bad = {k: counts.get(k, 0) for k in ("hash_mismatch", "corrupt_body", "unlinked", "malformed")}
        if any(bad.values()):
            logger.warning(
                "index header fill (%s): refused %s — those entries were NOT changed",
                where, ", ".join(f"{k}={v}" for k, v in bad.items() if v),
            )

    # -- peer path -----------------------------------------------------------

    def locator(self) -> list[bytes] | None:
        """``getheaders`` locator for the outstanding run: the hash one below
        its first height (whose entry the run's first header must link to).
        For a run starting at genesis it is empty, and :meth:`hash_stop` names
        genesis: Core answers an empty locator with the hashStop header alone
        (net_processing.cpp ProcessMessage GETHEADERS, ``locator.IsNull()``)."""
        if not self.peer_run:
            return None
        first_h = self.peer_run[0][0]
        if first_h == 0:
            return []
        prev = self.db.get_block_hash_by_height(first_h - 1)
        if prev is None or len(bytes(prev)) != 32:
            return None
        return [bytes(prev)]

    def hash_stop(self) -> bytes:
        if self.peer_run and self.peer_run[0][0] == 0:
            return self.peer_run[0][1]
        return b"\x00" * 32

    def wants(self, raw_headers: Sequence[bytes]) -> bool:
        """True when this headers reply answers the outstanding run (its first
        header's parent is the locator hash; at genesis, it IS genesis).
        Non-mutating."""
        if not self.peer_run or not raw_headers or len(raw_headers[0]) < 80:
            return False
        loc = self.locator()
        if loc is None:
            return False
        if not loc:
            return dsha(bytes(raw_headers[0][:80])) == self.peer_run[0][1]
        return bytes(raw_headers[0][4:36]) == loc[0]

    def accept(self, raw_headers: Sequence[bytes]) -> dict:
        """Attach a reply to the outstanding run (blocking; thread + chain
        lock).  Only the headers whose hash is a run member are offered; the
        rest of the reply is ignored.  The run is cleared once every member
        is attached; a member the peer did not serve keeps the run open."""
        want = {k for _h, k in self.peer_run}
        mine = []
        for raw in raw_headers:
            raw = bytes(raw[:80])
            if len(raw) == 80 and dsha(raw) in want:
                mine.append(raw)
        served = {dsha(r) for r in mine}
        remaining = [(h, k) for h, k in self.peer_run if k not in served]
        resume = remaining[0][0] if remaining else self.next_height
        counts = self.db.attach_index_headers(mine, resume, True)
        self._add(counts)
        self._log_refusals(counts, "peer headers")
        # Members the reply did not serve stay in the run (the caller asks
        # another peer).  A served member that failed attach's checks
        # (unlinked) is counted and leaves the run: the same header from any
        # peer would fail the same way, and its entry is left unchanged.
        if remaining:
            still = []
            for h, k in remaining:
                e = self.db.get_block_index_entry(k)
                if e is None or e[4] is None:
                    still.append((h, k))
            remaining = still
        self.peer_run = remaining
        self.req_locator = None
        return counts

    def summary(self) -> str:
        c = self.counts
        return (
            f"from_headers={c['from_headers']} from_body={c['from_body']} "
            f"attached={c['attached']} hash_mismatch={c['hash_mismatch']} "
            f"corrupt_body={c['corrupt_body']} unlinked={c['unlinked']} "
            f"unknown={c['unknown']} no_source={c['no_source']} "
            f"next_height={self.next_height}"
        )


async def run_step(fill: IndexHeaderFill, lock) -> dict:
    """One local step under ``lock`` (the node's chain lock), in a thread."""
    async with lock:
        return await asyncio.to_thread(fill.step)


async def run_accept(fill: IndexHeaderFill, raw_headers: Sequence[bytes], lock) -> dict:
    async with lock:
        return await asyncio.to_thread(fill.accept, list(raw_headers))


def dry_run(raw_db: Any, *, max_scan: int = 100_000) -> dict:
    """Both passes with ``write=False`` from the start: what the fill would
    do on this database.  Never writes (usable on a RocksDB secondary).

    ``need_peer`` = active-chain entries that need a header from a peer;
    ``no_source`` = off-chain entries no source can fill; ``fillable_local``
    = entries a local store fills; the refusal counts are entries the fill
    would leave unchanged because a stored header or body did not verify.
    """
    t0 = time.time()
    total: dict[str, int] = {k: 0 for k in COUNT_KEYS}
    h, done = 0, False
    while not done:
        counts, h, done, _run = raw_db.fill_index_headers_by_height(h, max_scan, 0, 0, False)
        for k, v in counts.items():
            total[k] = total.get(k, 0) + int(v)
    by_height = dict(total)
    key: bytes | None = None
    key_total: dict[str, int] = {}
    done = False
    while not done:
        counts, key, done = raw_db.fill_index_headers_by_hash(key, max_scan, 0, False)
        key = bytes(key) if key is not None else None
        for k, v in counts.items():
            key_total[k] = key_total.get(k, 0) + int(v)
    out = {
        "active_scanned": by_height.get("scanned", 0),
        "active_already_v2": by_height.get("already_v2", 0),
        # The by-key pass skips active-chain entries, so nothing is counted twice.
        "fillable_local": by_height.get("from_headers", 0) + by_height.get("from_body", 0)
        + key_total.get("from_headers", 0) + key_total.get("from_body", 0),
        "need_peer": by_height.get("need_peer", 0),
        "no_source": key_total.get("no_source", 0),
        "hash_mismatch": by_height.get("hash_mismatch", 0) + key_total.get("hash_mismatch", 0),
        "corrupt_body": by_height.get("corrupt_body", 0) + key_total.get("corrupt_body", 0),
        "unlinked": by_height.get("unlinked", 0) + key_total.get("unlinked", 0),
        "malformed": by_height.get("malformed", 0) + key_total.get("malformed", 0),
        "no_entry": by_height.get("no_entry", 0),
        "index_entries": key_total.get("scanned", 0),
        "index_legacy": key_total.get("scanned", 0) - key_total.get("already_v2", 0)
        - key_total.get("malformed", 0),
        "off_chain_legacy": key_total.get("scanned", 0) - key_total.get("already_v2", 0)
        - key_total.get("malformed", 0) - key_total.get("need_peer", 0),
        "seconds": round(time.time() - t0, 3),
    }
    return out
