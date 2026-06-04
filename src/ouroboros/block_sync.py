"""
Ongoing block synchronization from the Bitcoin network.

This module implements continuous block synchronization after initial sync,
handling new block announcements, validation, and chain reorganization.
"""

import asyncio
import hashlib
import logging
import os
import random
import threading
import time
from collections import Counter, defaultdict, deque
from collections.abc import Callable
from typing import Optional

# B3 Stage 1: IBD-drain validate_block runs through the Rust FFI (off-GIL)
# by default.  Matches Python's skip_scripts=True semantics, and only
# engaged when the sync module is present and the current block is below
# the assume-valid checkpoint.  The W90/W91 soak (2026-04-22) confirmed
# ~2.3× validate speedup with zero fallbacks or cross-check mismatches
# across >400 blocks, so this path flipped from opt-in to default-on.
# Set OUROBOROS_DISABLE_RUST_VALIDATE=1 to force the Python validator.
try:
    import sync as _sync_module
    _has_sync_module = True
except ImportError:
    _sync_module = None
    _has_sync_module = False

# B3 Stage 1 cross-check: OUROBOROS_VALIDATE_CROSS_CHECK=1 runs BOTH
# validators and logs mismatches.  Counters exposed via
# get_cross_check_stats() for the RPC layer.  Trust Python (Rust is
# advisory during the cross-check window).
_CROSS_CHECK_MAX_SAMPLES = 32
_cross_check_lock = threading.Lock()
_cross_check_stats: dict = {
    "matches": 0,
    "mismatches": 0,
    "samples": [],  # recent mismatches: {"height", "rust": (v,e), "python": (v,e)}
}


def get_cross_check_stats() -> dict:
    """Return a snapshot of the validate-path cross-check counters.

    Used by the RPC layer (``get_cross_check_stats``) to surface
    mismatch counts during the B3 Stage 1 soak window.
    """
    with _cross_check_lock:
        return {
            "matches": _cross_check_stats["matches"],
            "mismatches": _cross_check_stats["mismatches"],
            "samples": list(_cross_check_stats["samples"]),
        }


def _record_cross_check(
    matched: bool,
    *,
    height: int,
    rust_result: tuple,
    python_result: tuple,
) -> None:
    with _cross_check_lock:
        if matched:
            _cross_check_stats["matches"] += 1
        else:
            _cross_check_stats["mismatches"] += 1
            samples = _cross_check_stats["samples"]
            samples.append(
                {
                    "height": height,
                    "rust": rust_result,
                    "python": python_result,
                }
            )
            if len(samples) > _CROSS_CHECK_MAX_SAMPLES:
                del samples[: len(samples) - _CROSS_CHECK_MAX_SAMPLES]

# Bitcoin Core net_processing.cpp: MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16.
# Bounds the damage a single slow peer can do during IBD — without this,
# the global 256-slot window divided across ~8 peers gives each peer ~32
# concurrent requests, so one peer stalling holds 32 blocks hostage for
# the full 20s timeout window.
MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16

# Bitcoin Core protocol.h:482: MAX_GETDATA_SZ = 1000.
# Peers reject GETDATA messages containing more than 1000 inventory items.
MAX_GETDATA_SZ = 1000

# Maximum number of re-request cycles a single block-download may incur in
# ``_handle_timeouts`` before it is permanently abandoned (dropped from the
# in-flight maps + perm-rejected) instead of being re-requested forever.
#
# Without this bound the at-tip RSS leak (2026-06-02/03 OOMs) accrued: peers
# at tip announce stale / competing / fork block hashes via ``inv`` that we
# dutifully request, but which never become part of our active chain and so
# never reach the ``handle_block`` -> connect path that pops them.
# ``_handle_timeouts`` re-armed ``requested_blocks`` / ``_block_request_peer``
# every cycle indefinitely (it only drops entries in the no-peers branch),
# and ``_w77_first_request_time`` was never touched by the timeout path at
# all — so every unique never-connecting requested hash leaked one entry in
# each of the three maps forever, and ``_block_request_peer`` holds live Peer
# references, keeping zombie Peers (transport buffers, BIP-324 state) alive.
# Core bounds this implicitly: a stalling block-download triggers
# BLOCK_DOWNLOAD_TIMEOUT_BASE disconnection of the peer and mapBlocksInFlight
# is torn down on FinalizeNode; there is no unbounded retain-and-retry queue.
BLOCK_REQUEST_MAX_ATTEMPTS = 10

# Hard cap on the ``_w77_first_request_time`` telemetry map.  It is
# diagnostic-only (request->connect latency rollup) and must NEVER be
# load-bearing for memory.  FIFO-evict the oldest entry past this cap.  This
# is a belt-and-braces backstop in addition to the per-hash cleanup the
# abandon / perm-reject paths now perform — the dict can never outgrow this
# regardless of any future path that forgets to clean an entry.
W77_FIRST_REQUEST_MAX_ENTRIES = 20_000

from ouroboros.database import Block, BlockchainDatabase, Transaction
from ouroboros.p2p_messages import (
    INV_TYPE_BLOCK,
    INV_TYPE_TX,
    MSG_WITNESS_BLOCK,
    MSG_WITNESS_TX,
    MSG_WTX,
    BlockHeader,
    CmpctBlockMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    InvMessage,
    NetworkMessage,
)
from ouroboros.config import MIN_BLOCKS_TO_KEEP
from ouroboros.peer import Peer
from ouroboros.validation import SIG_CACHE, BlockValidator

logger = logging.getLogger(__name__)


# Bitcoin Core's ``MAX_NUM_UNCONNECTING_HEADERS_MSGS`` from
# ``net_processing.cpp``.  A peer that delivers more than this many
# successive unconnecting-headers messages is misbehavior-scored and
# disconnected.  Tolerating up to 10 transient unlinked batches
# matches Core and prevents banning honest peers caught in a brief
# reorg, while still bounding the soft-DoS surface where a malicious
# peer keeps us in an infinite getheaders/orphan loop.
_MAX_NUM_UNCONNECTING_HEADERS_MSGS: int = 10


def _distribute_blocks_round_robin(
    items: list,
    candidates: list,
    peer_load: dict,
    max_per_peer: int,
) -> tuple[dict, list]:
    """Round-robin distribute items across candidates, respecting per-peer cap.

    ``peer_load`` is mutated in place to reflect new assignments so callers
    can chain multiple distribution passes.  Returns ``(per_peer, assigned)``
    where ``per_peer`` is a ``candidate -> [items]`` dict covering every
    candidate (possibly with empty lists) and ``assigned`` is the subset of
    ``items`` that was placed.  Any remaining items are deferred — all
    candidates were at cap when iteration stopped.
    """
    per_peer: dict = {c: [] for c in candidates}
    assigned: list = []
    if not candidates:
        return per_peer, assigned
    n = len(candidates)
    peer_idx = 0
    for item in items:
        for attempt in range(n):
            target = candidates[(peer_idx + attempt) % n]
            if peer_load.get(target, 0) < max_per_peer:
                per_peer[target].append(item)
                peer_load[target] = peer_load.get(target, 0) + 1
                assigned.append(item)
                peer_idx = (peer_idx + attempt + 1) % n
                break
        else:
            # All candidates at cap — stop trying further items this round.
            break
    return per_peer, assigned


class BlockSync:
    """Synchronizes new blocks from network"""

    def __init__(
        self,
        db: BlockchainDatabase,
        validator: BlockValidator,
        peer_manager,  # PeerManager or compatible interface
        mempool=None,  # Optional mempool for re-adding txs after reorg
        fee_estimator=None,  # Optional FeeEstimator to feed confirmed-block fee data
        block_filter_index=None,  # Optional BIP 157/158 block-filter index
    ):
        """Initialize block synchronizer."""
        self.db = db
        self.validator = validator
        self.peer_manager = peer_manager
        self.mempool = mempool
        self.fee_estimator = fee_estimator
        # BIP 157/158 — when set, every successfully connected block is
        # passed to ``block_filter_index.add_block(block, height)`` so the
        # index stays in lock-step with the chain tip.  None = disabled.
        self.block_filter_index = block_filter_index

        # Track requested blocks (hash -> request_time)
        # FIXME: race condition if called from multiple threads?
        self.requested_blocks: dict[bytes, float] = {}

        # Track which peer each block was last requested from (hash -> Peer)
        self._block_request_peer: dict[bytes, Peer] = {}

        # W77 — peer-timeout instrumentation.  100-block rollup emitted
        # from _drain_block_buffer_locked at the connect point.  The
        # per-cycle WARNING in _handle_timeouts obscures aggregate churn;
        # this rollup captures timeouts/cycle, failed-peer fan-out,
        # re-request distribution and request→connect latency.
        #
        # _w77_first_request_time retains the ORIGINAL request time;
        # self.requested_blocks is mutated on re-request and loses it.
        self._w77_blocks: int = 0
        self._w77_timeouts_total: int = 0
        self._w77_timeout_cycles: int = 0
        self._w77_failed_peers: set = set()
        self._w77_rerequest_peer_counts: Counter = Counter()
        self._w77_latency_sum_s: float = 0.0
        self._w77_latency_max_s: float = 0.0
        self._w77_first_request_time: dict[bytes, float] = {}
        # Insertion-order FIFO companion for the hard cap on the telemetry map.
        self._w77_first_request_order: deque[bytes] = deque()

        # Per-block re-request attempt counter (block_hash -> int).  Bumped on
        # every re-request in _handle_timeouts; a block that exceeds
        # BLOCK_REQUEST_MAX_ATTEMPTS is permanently abandoned (see
        # _abandon_block_request) rather than re-requested forever.  This is
        # what bounds requested_blocks / _block_request_peer for blocks a peer
        # announced but no peer will ever deliver into our active chain (stale
        # / fork / competing tips at the at-tip churn path — the 2026-06-02/03
        # OOM driver).  Cleared in lockstep with the in-flight maps.
        self._block_request_attempts: dict[bytes, int] = {}

        # W95 — recent-block-size EMA (MB), used by _handle_timeouts to
        # scale the general block-download timeout with payload size.
        # Initialised at 1.0 MB (roughly the mainnet average post-500k);
        # updated on every received block in handle_block.  Small alpha
        # keeps the signal smooth — we care about the bulk height
        # trend, not spikes from individual oversized blocks.
        self._w95_block_mb_ema: float = 1.0
        self._w95_block_mb_alpha: float = 0.05

        # Track requested transactions (hash -> request_time)
        self._requested_txs: dict[bytes, float] = {}

        # Track received blocks (hash -> Block)
        self.received_blocks: dict[bytes, Block] = {}

        # Orphan blocks: hash -> Block (blocks whose parent is not in our chain)
        # Ref: bitcoin/src/net_processing.cpp orphan_work_set, ProcessOrphanTx
        self.orphan_blocks: dict[bytes, Block] = {}
        self._max_orphans = 200

        # Track pending headers requests
        self.pending_headers: dict[bytes, float] = {}  # locator_hash -> request_time

        # Reorg detection
        self.last_best_hash: bytes | None = None
        self.reorg_depth: int = 0

        self._zmq_publisher = None

        self.running = False
        self._sync_task: asyncio.Task | None = None

        # Message handlers per peer (peer -> handler_dict)
        self._peer_handlers: dict[Peer, dict[str, Callable]] = defaultdict(dict)

        # Headers-first sync: validated header chain waiting for block download.
        # List of (block_hash, header) in chain order (oldest first).
        self._validated_headers: list[tuple[bytes, BlockHeader]] = []
        # Max blocks to have in-flight at once during headers-first sync.
        self._max_blocks_in_flight: int = 256

        # Per-peer counter of consecutive unconnecting-headers messages.
        # Mirrors Bitcoin Core's ``nUnconnectingHeaders`` accounting in
        # ``net_processing.cpp::ProcessHeadersMessage``.  Keyed by peer
        # ``host:port`` string.  Incremented on every header batch whose
        # first header doesn't connect; reset on any successful
        # connecting batch.  When the counter would exceed
        # ``_MAX_NUM_UNCONNECTING_HEADERS_MSGS`` (=10) we
        # ``misbehaving(20)`` the peer.  Pre-fix, ouroboros silently
        # ``break``ed out of the per-header loop on orphan with no
        # penalty — a malicious peer could keep us in a getheaders
        # loop forever.  See
        # ``CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md``
        # (Pattern B), extended to Part-2 impls.
        self._unconnecting_headers_count: dict[str, int] = {}

        # Single sync peer for header downloads (Bitcoin Core pattern).
        # Only one peer is sent getheaders at a time to prevent out-of-order
        # header batches.  Switches to a different peer after a stall.
        self._header_sync_peer: Peer | None = None
        self._header_sync_time: float = 0.0  # When the last getheaders was sent
        self._header_sync_stall_timeout: float = 30.0  # Switch peer after 30s

        # IBD block buffer: blocks that arrived out of order are held here
        # keyed by block_hash until their parent is connected.  After each
        # successful connect, _drain_block_buffer() processes buffered
        # children sequentially.
        self._ibd_block_buffer: dict[bytes, Block] = {}
        self._max_ibd_buffer: int = 1024

        # Drain-loop stage timings (W60 B0, promoted to W76-PHASE cross-
        # impl phase table).  Accumulates wall-clock ns spent in each
        # stage since the last summary log, plus per-phase max for tail
        # latency.  Emitted every _w76_log_every blocks connected, then
        # reset.  Ouroboros's three-phase split (deserialize / validate
        # / connect) maps to blockbrew's W76 boundaries as
        # pre≈deserialize, first+script≈validate (conflated inside the
        # Rust FFI), persist≈connect.
        self._w76_blocks: int = 0
        self._w76_deserialize_sum_ns: int = 0
        self._w76_validate_sum_ns: int = 0
        self._w76_connect_sum_ns: int = 0
        self._w76_deserialize_max_ns: int = 0
        self._w76_validate_max_ns: int = 0
        self._w76_connect_max_ns: int = 0
        self._w76_log_every: int = 1000

        # W90 validation-path probe (2026-04-22).  W76-PHASE pins ~90% of
        # per-block wall-clock on the 'validate' stage but doesn't say
        # which validator ran or how the cost scales with tx count.  W90
        # splits validate by path (Rust fast-path vs Python), records
        # whether assumevalid's skip_scripts was in effect, and rolls up
        # a per-tx cost estimate every 100 blocks.  Diagnostic only —
        # remove once the W85 regression is root-caused.
        self._w90_blocks: int = 0
        self._w90_rust_used: int = 0
        self._w90_python_used: int = 0
        self._w90_skip_scripts_true: int = 0
        self._w90_tx_count_sum: int = 0
        self._w90_validate_sum_ns: int = 0
        self._w90_validate_max_ns: int = 0
        self._w90_slow_blocks: int = 0
        self._w90_log_every: int = 100
        self._w90_slow_threshold_ns: int = 8_000_000_000  # 8s

        # W91 drain-loop wall-clock probe (2026-04-22).  W90 showed the
        # validator drops 2.3× with Rust+skip_scripts but overall rate
        # got WORSE (−31%), meaning the 'non-work' budget per block
        # ballooned from ~138s/100-blocks to ~714s/100-blocks.  W91
        # splits that non-work time into (a) intra-drain async/DB
        # overhead (gap = wallclock − deser − val − con per block) and
        # (b) time the drain loop was idle between invocations
        # (drain_idle = entry_time − prev_exit_time).  A high
        # drain_idle_avg means peer delivery is rate-limiting; a high
        # gap_avg means connect / mempool / asyncio.sleep is the hotspot.
        self._w91_blocks: int = 0
        self._w91_wallclock_sum_ns: int = 0
        self._w91_wallclock_max_ns: int = 0
        self._w91_work_sum_ns: int = 0
        self._w91_last_connect_perf_ns: int = 0  # 0 = uninitialised
        self._w91_drain_entries: int = 0
        self._w91_drain_noprogress: int = 0
        self._w91_drain_idle_sum_ns: int = 0
        self._w91_drain_idle_max_ns: int = 0
        self._w91_last_drain_exit_perf_ns: int = 0
        self._w91_buffer_on_entry_sum: int = 0
        self._w91_log_every: int = 100

        # Serializes `_drain_block_buffer` against itself.  The drain is
        # invoked from both `sync_loop` (periodic) and `handle_block`
        # (every incoming P2P block); without this lock two drains can
        # interleave, each awaiting `asyncio.to_thread(validate)` while
        # the other runs `connect_block_from_bytes` (mutates UTXO set).
        # That produced cross-check mismatches where Rust validated
        # against the pre-mutation UTXO and Python against the post-
        # mutation UTXO.  Lazy-init: asyncio.Lock() needs a running loop.
        self._drain_lock: asyncio.Lock | None = None

        # W75-WATCHDOG: block-accept outcome counters + staleness guard.
        # Motivated by the 2026-04-14..19 wedge where the running
        # process accepted headers + requested blocks for 5 days but
        # tip never advanced past 801188.  Restart cleared the wedge
        # (see wave47-2026-04-16/W75-OUROBOROS-STALL.md).  These
        # counters + the watchdog check in `sync_loop` will surface
        # the next recurrence in-process instead of requiring an
        # external operator to notice height staleness.
        self._blk_received: int = 0
        self._blk_too_short: int = 0
        self._blk_duplicate: int = 0
        self._blk_buffered: int = 0
        self._blk_buffer_full: int = 0
        self._blk_error: int = 0
        self._blk_connected: int = 0
        self._blk_validate_rejected: int = 0
        self._blk_connect_failed: int = 0
        self._last_tip_advance: float = time.time()

        # Permanent reject set: hashes of blocks whose validation deterministically
        # failed (NOT including transient "Previous block not found").  When peers
        # redeliver a perm-rejected block, handle_block drops it without re-buffering
        # so we don't spin retrying the same bad bytes.  Capped at
        # ``_perm_rejected_max`` entries (FIFO eviction) to bound memory.
        self._perm_rejected_blocks: set[bytes] = set()
        self._perm_rejected_order: list[bytes] = []
        self._perm_rejected_max: int = 10000
        self._blk_perm_rejected_dropped: int = 0
        # Track which peer (as "host:port" string) delivered each buffered block
        # so the drain loop can score Misbehaving(100) against the right peer when
        # it finds BLOCK_MUTATED or BLOCK_INVALID_HEADER.  Entry cleared on
        # successful connect or on permanent rejection.
        self._block_source_peer_addr: dict[bytes, str] = {}
        # Fire WARN once per _wedge_warn_every if no-advance > _wedge_warn_after.
        self._wedge_warn_after: float = 300.0
        self._wedge_warn_every: float = 300.0
        self._last_wedge_warn: float = 0.0

        # BIP-130 / Core HeadersSyncState (PRESYNC/REDOWNLOAD anti-DoS).
        # Per-peer Rust state machine that tracks cumulative work +
        # 1-bit commitments during initial header sync.  Implemented in
        # `ferrous-utils/sync/src/validate/headers_presync.rs` and
        # exposed via `sync.PyHeadersSyncState`.  Pre-2026-05-06 the
        # production handler bypassed this and only checked chain
        # continuity — see CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-
        # audit-2026-05-06-part2.md, RED finding #1.  Keyed by
        # (host, port); recreated when the sync peer changes or when
        # the state finalizes (success or failure).
        self._presync_states: dict[tuple[str, int], object] = {}
        # Counters for the per-header PoW gate (used by tests + ops).
        self._headers_pow_rejected: int = 0
        self._headers_presync_failures: int = 0

    def set_zmq_publisher(self, publisher) -> None:
        """Attach a ZMQPublisher for real-time block/tx notifications."""
        self._zmq_publisher = publisher

    def _mark_perm_rejected(self, block_hash: bytes) -> None:
        """Add *block_hash* to the permanent-reject set, evicting the oldest
        entry once the set is full.  Idempotent: re-adding an existing hash
        does not advance the FIFO position.

        Also drops the hash from every block-request bookkeeping map: a
        perm-rejected block was delivered, validated-invalid, and will never
        reach the ``handle_block`` -> connect path that pops these.  Before
        this cleanup the ``_w77_first_request_time`` entry in particular
        leaked permanently (it is only popped by ``_w77_record_connect`` on a
        successful active-chain connect) — one leaked entry per perm-rejected
        block, an at-tip RSS-leak contributor.
        """
        self._abandon_block_request(block_hash)
        if block_hash in self._perm_rejected_blocks:
            return
        if len(self._perm_rejected_order) >= self._perm_rejected_max:
            evicted = self._perm_rejected_order.pop(0)
            self._perm_rejected_blocks.discard(evicted)
        self._perm_rejected_blocks.add(block_hash)
        self._perm_rejected_order.append(block_hash)

    def _record_first_request_time(self, block_hash: bytes, now: float) -> None:
        """Record the original request time for *block_hash* with a hard FIFO
        cap on ``_w77_first_request_time``.

        ``_w77_first_request_time`` is request->connect latency telemetry; it
        is only popped on a successful connect (``_w77_record_connect``), so a
        requested-but-never-connecting block (stale / fork / competing tip
        announced at the at-tip churn path) would otherwise leak its entry
        forever.  The per-hash cleanup in ``_abandon_block_request`` handles
        the common cases; this cap is the unconditional backstop that bounds
        the map regardless of any future path that forgets to clean up.
        """
        if block_hash in self._w77_first_request_time:
            return
        self._w77_first_request_time[block_hash] = now
        self._w77_first_request_order.append(block_hash)
        while len(self._w77_first_request_time) > W77_FIRST_REQUEST_MAX_ENTRIES:
            oldest = self._w77_first_request_order.popleft()
            self._w77_first_request_time.pop(oldest, None)

    def _abandon_block_request(self, block_hash: bytes) -> None:
        """Drop *block_hash* from every in-flight block-request map.

        Used when a requested block leaves the "wanted" state without a
        successful connect: permanent rejection, or exhausting
        ``BLOCK_REQUEST_MAX_ATTEMPTS`` re-request cycles for a block no peer
        will deliver into our active chain.  Keeps ``requested_blocks``,
        ``_block_request_peer`` (which holds live Peer references — leaking it
        pins zombie Peers), ``_w77_first_request_time`` and the attempt
        counter bounded.  Idempotent; safe on unknown hashes.
        """
        self.requested_blocks.pop(block_hash, None)
        self._block_request_peer.pop(block_hash, None)
        self._w77_first_request_time.pop(block_hash, None)
        self._block_request_attempts.pop(block_hash, None)

    # BIP34 activation height (mainnet).  Below this height the coinbase
    # scriptSig is unconstrained; above it the first push must encode the
    # block's height as little-endian CScriptNum.
    _BIP34_ACTIVATION_HEIGHT = 227_931

    @staticmethod
    def _decode_bip34_height(coinbase_script_sig: bytes) -> int | None:
        """Decode the BIP34-encoded height from a coinbase ``scriptSig``.

        Returns ``None`` if the scriptSig does not match the BIP34 shape we
        can decode (push-size 1..4, push fits within scriptSig).  This is
        not a consensus check — callers compare against an expected height
        and raise on mismatch.
        """
        if len(coinbase_script_sig) < 2:
            return None
        push_size = coinbase_script_sig[0]
        if push_size < 1 or push_size > 4:
            return None
        if 1 + push_size > len(coinbase_script_sig):
            return None
        return int.from_bytes(coinbase_script_sig[1:1 + push_size], "little")

    def _coinbase_height_mismatch(self, block, expected_height: int) -> bool:
        """True if the block's BIP34-encoded coinbase height disagrees with
        ``expected_height`` at heights where BIP34 is active.

        This is a slot-alignment guard, not a script-level consensus check
        (the validator does the full BIP34 enforcement).  A True here means
        the block we are about to validate at slot N is not actually the
        block at chain height N — the validated-header queue is corrupt.
        """
        if expected_height < self._BIP34_ACTIVATION_HEIGHT:
            return False
        try:
            txs = getattr(block, "transactions", None)
            if not txs:
                return False
            coinbase = txs[0]
            inputs = getattr(coinbase, "inputs", None)
            if not inputs:
                return False
            script_sig = inputs[0].script_sig
        except (AttributeError, IndexError, TypeError):
            return False
        encoded = self._decode_bip34_height(script_sig)
        if encoded is None:
            # scriptSig isn't BIP34-decodable; let the validator handle it.
            return False
        return encoded != expected_height

    def _handle_misaligned_block(
        self, block_hash: bytes, expected_height: int, block
    ) -> None:
        """Recovery path when a buffered block's BIP34 height does not match
        the slot we were about to validate it at.

        The queue index is corrupt: slot 0 of ``_validated_headers`` is the
        header of a block several heights above our actual chain tip, which
        is what triggered the 938231 vs 938349 wedge after a
        ``dumptxoutset`` rollback.  Discard the validated-header queue and
        the IBD block buffer, clear in-flight tracking, and let the next
        ``sync_loop`` tick rebuild the header chain from our real tip.

        The block is NOT marked as ``_perm_rejected_blocks``: its bytes are
        canonical mainnet data, just delivered at the wrong slot.  Marking
        it permanently rejected would also discard valid future redeliveries
        once the queue is realigned.
        """
        encoded = None
        try:
            encoded = self._decode_bip34_height(block.transactions[0].inputs[0].script_sig)
        except Exception:
            pass
        logger.error(
            "[slot-misalign] BIP34 height %s != expected slot %d for block "
            "%s — rebuilding validated_headers from chain tip "
            "(queue=%d, buffer=%d, in-flight=%d)",
            encoded,
            expected_height,
            block_hash.hex()[:16],
            len(self._validated_headers),
            len(self._ibd_block_buffer),
            len(self.requested_blocks),
        )
        self._validated_headers.clear()
        self._ibd_block_buffer.clear()
        self.requested_blocks.clear()
        self._block_request_peer.clear()
        self._block_source_peer_addr.clear()
        # _w77_first_request_time is the request→connect latency telemetry
        # dict; it pops only on a successful active-chain connect, so a bulk
        # queue-drop here would otherwise orphan every in-flight entry.
        # Clear it alongside the sibling maps (telemetry-only, safe to reset).
        self._w77_first_request_time.clear()
        self._w77_first_request_order.clear()
        self._block_request_attempts.clear()
        # Reset the header-sync stall timer so sync_loop picks a fresh
        # header sync peer immediately rather than waiting out the previous
        # peer's stall window.
        self._header_sync_peer = None
        self._header_sync_time = 0.0

    async def start(self):
        """Start block synchronization"""
        if self.running:
            logger.warning("BlockSync already running")
            return

        self.running = True
        logger.info("Starting block synchronization")

        # W90: log the validation-path env-var state once at startup so
        # we can correlate later [W90-VAL] rollups with the flag config
        # the process actually booted with.
        logger.info(
            "[W90-INIT] rust_validate_default=True "
            "disabled_by_env=%s cross_check=%s "
            "has_sync_module=%s has_validate_block_from_bytes=%s",
            os.environ.get("OUROBOROS_DISABLE_RUST_VALIDATE") == "1",
            os.environ.get("OUROBOROS_VALIDATE_CROSS_CHECK") == "1",
            _has_sync_module,
            hasattr(self.db, "validate_block_from_bytes"),
        )

        # Register message handlers for existing peers
        await self._register_handlers()

        # Start sync task
        self._sync_task = asyncio.create_task(self.sync_loop())

    async def stop(self):
        """Stop block synchronization"""
        if not self.running:
            return

        logger.info("Stopping block synchronization")
        self.running = False

        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

        # Unregister handlers
        for peer in list(self._peer_handlers.keys()):
            await self._unregister_handlers(peer)

    async def _register_handlers(self):
        # Get all ready peers (assuming peer_manager has this method)
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            # Fallback: try to get peers from peer_manager.peers
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = [p for p in peers.values() if hasattr(p, 'is_connected') and p.is_connected()]
            elif not isinstance(peers, list):
                peers = []

        for peer in peers:
            if not isinstance(peer, Peer):
                continue

            # Register handlers
            peer.register_handler("inv", self._make_inv_handler(peer))
            peer.register_handler("block", self._make_block_handler(peer))
            peer.register_handler("headers", self._make_headers_handler(peer))

            self._peer_handlers[peer] = {
                "inv": self._make_inv_handler(peer),
                "block": self._make_block_handler(peer),
                "headers": self._make_headers_handler(peer),
            }

    async def _unregister_handlers(self, peer: Peer):
        # Note: Peer class doesn't have unregister_handler, so we just remove from tracking
        if peer in self._peer_handlers:
            del self._peer_handlers[peer]

    def cleanup_peer(self, addr: str) -> None:
        """Drop all per-peer state associated with *addr* ("host:port").

        Called from ``PeerManager._cleanup_peer_state`` on disconnect.
        Before ouroboros #146 every per-peer map here grew unbounded over
        the process lifetime (no disconnect callback fired into block_sync),
        which combined with the much-larger ``TrickleQueue.known_filter``
        leak to wedge PID 1771536 (RSS 58 GB / swap 89 GB).

        The single largest item is ``_peer_handlers[peer]``, whose values
        are closures over both ``peer`` and ``self`` — leaving them in the
        dict keeps the *entire* zombie Peer alive (including its socket
        readers, BIP-324 transport state, message buffers, ...).
        """
        # ``_peer_handlers`` is keyed by Peer object, not addr string.  Match
        # by host:port — the same shape ``_peer_key`` uses.
        peers_to_drop = [
            p for p in list(self._peer_handlers.keys())
            if f"{getattr(p, 'host', '?')}:{getattr(p, 'port', '?')}" == addr
        ]
        for p in peers_to_drop:
            self._peer_handlers.pop(p, None)

        self._unconnecting_headers_count.pop(addr, None)

        # ``_block_request_peer`` is keyed by block-hash but holds Peer
        # values, so a disconnected peer still mid-request stays alive
        # through this dict until the request times out or completes.
        # Drop any entries pointing at the disconnected peer so the Peer
        # object can be GC'd promptly; the next sync_loop tick will
        # re-request these blocks from a live peer via the timeout path.
        hashes_to_drop = [
            bh for bh, p in list(self._block_request_peer.items())
            if p is not None
            and f"{getattr(p, 'host', '?')}:{getattr(p, 'port', '?')}" == addr
        ]
        for bh in hashes_to_drop:
            self._block_request_peer.pop(bh, None)
            # Drop the source-addr breadcrumb too so the next delivery
            # of the same block from a different peer is not credited
            # to the disconnected one.
            self._block_source_peer_addr.pop(bh, None)

        # ``_presync_states`` is keyed by (host, port) tuple.  Split and pop.
        if ":" in addr:
            host, port_str = addr.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
            if port is not None:
                self._presync_states.pop((host, port), None)

    def _make_inv_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            await self.handle_inv(msg, peer)
        return handler

    def _make_block_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            await self.handle_block(msg, peer)
        return handler

    def _make_headers_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            # Raw P2P headers from a peer have NOT been cleared by the
            # PRESYNC state machine yet — pass min_pow_checked=False so
            # that handle_headers enforces the G8 nMinimumChainWork gate
            # (Bitcoin Core validation.cpp:4229).
            await self.handle_headers(msg, peer, min_pow_checked=False)
        return handler

    def _register_new_peers(self):
        """Register handlers for any newly connected peers."""
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = list(peers.values())
        new_count = 0
        for peer in peers:
            if not isinstance(peer, Peer):
                continue
            if peer in self._peer_handlers:
                continue
            peer.register_handler("inv", self._make_inv_handler(peer))
            peer.register_handler("block", self._make_block_handler(peer))
            peer.register_handler("headers", self._make_headers_handler(peer))
            self._peer_handlers[peer] = {
                "inv": self._make_inv_handler(peer),
                "block": self._make_block_handler(peer),
                "headers": self._make_headers_handler(peer),
            }
            new_count += 1
        if new_count:
            logger.info(f"Registered block_sync handlers for {new_count} new peers (total: {len(self._peer_handlers)})")

    async def sync_loop(self):
        """Main synchronization loop"""
        while self.running:
            try:
                # Register handlers for any new peers
                self._register_new_peers()

                # Check if we're behind
                best_hash, best_height = self.db.get_best_block()

                # Detect reorgs.  Off-load the two full-block FFI
                # deserializes so a tip flip in the sync_loop tick does
                # not stall the event loop for the ~1-2 ms × block_size
                # PyO3 round-trip — the sync_loop sleeps only 1 s between
                # ticks during IBD, so even one stalled tick visibly
                # extends the RPC latency tail.
                if self.last_best_hash and self.last_best_hash != best_hash:
                    # Check if this is a reorg
                    current_block = await asyncio.to_thread(
                        self.db.get_block, best_hash,
                    )
                    if current_block:
                        prev_block = await asyncio.to_thread(
                            self.db.get_block, current_block.prev_blockhash,
                        )
                        if prev_block and prev_block.height and best_height:
                            if prev_block.height < best_height - 1:
                                logger.warning(
                                    f"Possible reorg detected: height {best_height}, "
                                    f"prev height {prev_block.height}"
                                )
                                # Get the block that's causing the reorg
                                # For now, use the best block as the new tip
                                await self._handle_reorg(prev_block, best_hash)

                self.last_best_hash = best_hash

                # Single-peer header sync (Bitcoin Core pattern).
                # Send getheaders to ONE designated peer at a time.
                # Switch peer if the current one stalls (no headers in 30s).
                now = time.time()
                if self._header_sync_peer and not self._header_sync_peer.is_connected():
                    self._header_sync_peer = None  # Peer disconnected

                if self._header_sync_peer and (now - self._header_sync_time > self._header_sync_stall_timeout):
                    # Sync peer stalled — switch to a different one.
                    # Core-parity NoBan exemption: a manually-pinned peer
                    # (-connect / -addnode) is NEVER discouraged or banned for
                    # stalling (net_processing.cpp MaybeDiscourageAndDisconnect:
                    # peers with NetPermissionFlags::NoBan are exempt; -connect
                    # implies that protection).  Scoring +50 here bans the peer
                    # at the DISCOURAGEMENT_THRESHOLD, and under -connect that is
                    # the ONLY peer — the ban then blocks every reconnect
                    # (connect_to_node refuses a banned addr), wedging the sync
                    # permanently with no alternative peer to "switch" to.  A
                    # slow loopback block fetch from a busy archival Core is not
                    # misbehaviour.  Skip the score for pinned peers; just rotate
                    # the designated sync peer (which re-selects the same pinned
                    # peer and resets the stall timer, giving the download more
                    # time).
                    is_pinned = bool(
                        getattr(self.peer_manager, "_connect_only", False)
                        or getattr(self._header_sync_peer, "is_manual", False)
                        or getattr(self._header_sync_peer, "noban", False)
                    )
                    logger.info(
                        "Header sync peer %s stalled, switching%s",
                        self._header_sync_peer.host,
                        " (pinned -connect peer: NoBan, not scored)" if is_pinned else "",
                    )
                    # Score misbehavior for stalling block downloads (+50) —
                    # only for non-pinned peers.
                    if self.peer_manager and not is_pinned:
                        from ouroboros.banman import SCORE_BLOCK_DOWNLOAD_STALL
                        self.peer_manager.misbehaving(
                            self._header_sync_peer.host, SCORE_BLOCK_DOWNLOAD_STALL,
                            "block download stalling")
                    self._header_sync_peer = None

                if not self._header_sync_peer:
                    self._header_sync_peer = self._get_sync_peer(best_height)
                    if self._header_sync_peer:
                        self._header_sync_time = now

                if self._header_sync_peer:
                    await self._catch_up(self._header_sync_peer, best_height)

                # Handle timeouts
                await self._handle_timeouts()

                # Drain any buffered blocks that can now be connected.
                await self._drain_block_buffer()

                # Advance headers-first download window (in case blocks
                # connected between sync_loop iterations).
                await self._request_next_blocks()

                # Prune validated headers that have been downloaded and connected.
                self._prune_validated_headers()

                # W75-WATCHDOG: surface the block-accept wedge class
                # (tip frozen despite non-empty buffer + pending headers).
                self._check_wedge_watchdog()

            except Exception as e:
                logger.error(f"Error in sync loop: {e}", exc_info=True)

            # During IBD, tick fast so timeout handling / re-requests don't
            # wait 10s.  After IBD (header queue drained), slow down.
            if self._validated_headers:
                await asyncio.sleep(1)
            else:
                await asyncio.sleep(10)

    async def handle_inv(self, msg: NetworkMessage, peer: Peer):
        """Handle inventory announcement (blocks + transactions)."""
        try:
            inv = InvMessage.from_payload(msg.payload)
            # logger.debug(f'inv from {peer.host}:{peer.port}, {len(inv.inventory)} items')

            blocks_to_request = []
            txs_to_request = []

            # Expire stale tx requests (>60 s)
            now = time.time()
            stale = [h for h, t in self._requested_txs.items() if now - t > 60]
            for h in stale:
                self._requested_txs.pop(h, None)

            has_new_blocks = False
            for inv_type, inv_hash in inv.inventory:
                if inv_type == INV_TYPE_BLOCK:
                    if not self.db.has_block_hash(inv_hash):
                        has_new_blocks = True
                        # Directly request the block if not already in-flight.
                        # This is critical for receiving blocks from mining
                        # peers promptly (e.g., regtest mesh tests) rather
                        # than waiting for the full headers-first round-trip.
                        #
                        # Bound the inv-triggered request path: skip hashes we
                        # already perm-rejected, and honour the global
                        # in-flight cap.  Without the cap a peer (or peers) at
                        # tip announcing many stale / fork / competing block
                        # hashes via inv could push requested_blocks /
                        # _block_request_peer / _w77_first_request_time
                        # arbitrarily high — none of those announces become
                        # part of our active chain, so they never reach the
                        # connect path that pops them (at-tip RSS-leak path,
                        # 2026-06-02/03 OOMs).
                        if (
                            inv_hash not in self.requested_blocks
                            and inv_hash not in self._perm_rejected_blocks
                            and len(self.requested_blocks) < self._max_blocks_in_flight
                        ):
                            blocks_to_request.append((MSG_WITNESS_BLOCK, inv_hash))
                            self.requested_blocks[inv_hash] = now
                            self._record_first_request_time(inv_hash, now)

                elif inv_type in (INV_TYPE_TX, MSG_WITNESS_TX, MSG_WTX):
                    # Request transactions we don't already have
                    if (
                        self.mempool
                        and not self.mempool.get_transaction(inv_hash)
                        and inv_hash not in self._requested_txs
                    ):
                        txs_to_request.append((MSG_WITNESS_TX, inv_hash))
                        self._requested_txs[inv_hash] = now

            network = (
                self.peer_manager.network
                if hasattr(self.peer_manager, "network")
                else "mainnet"
            )

            if has_new_blocks:
                # Don't send getheaders here — let the sync_loop's single-peer
                # approach handle it.  Sending getheaders to the inv peer AND
                # the sync peer creates overlapping header batches that arrive
                # out of order and get dropped.  Instead, just designate this
                # peer as the sync peer if we don't have one.
                if not self._header_sync_peer or not self._header_sync_peer.is_connected():
                    self._header_sync_peer = peer
                    self._header_sync_time = time.time()
                    logger.info(
                        f"Block inv from {peer.host}:{peer.port} — "
                        f"set as header sync peer"
                    )

            if blocks_to_request:
                getdata = GetDataMessage(inventory=blocks_to_request)
                try:
                    await peer.send_message(getdata.to_network_message(network))
                    for _, bh in blocks_to_request:
                        self._block_request_peer[bh] = peer
                    logger.info(
                        f"Requested {len(blocks_to_request)} blocks directly "
                        f"from {peer.host}:{peer.port} (inv-triggered)"
                    )
                except Exception as e:
                    logger.error(f"Failed to request blocks: {e}")

            if txs_to_request:
                # Cap each GETDATA at MAX_GETDATA_SZ=1000 items (Core protocol.h:482).
                # Peers reject GETDATA messages with more than 1000 inventory items.
                for i in range(0, len(txs_to_request), MAX_GETDATA_SZ):
                    batch = txs_to_request[i:i + MAX_GETDATA_SZ]
                    getdata = GetDataMessage(inventory=batch)
                    try:
                        await peer.send_message(getdata.to_network_message(network))
                        logger.debug(
                            f"Requested {len(batch)} txs from "
                            f"{peer.host}:{peer.port}"
                            + (f" (batch {i // MAX_GETDATA_SZ + 1})" if len(txs_to_request) > MAX_GETDATA_SZ else "")
                        )
                    except Exception as e:
                        logger.error(f"Failed to request txs: {e}")
                        break

        except Exception as e:
            logger.error(f"Error handling inv from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)

    async def handle_block(self, msg: NetworkMessage, peer: Peer):
        """Handle block delivery.

        During IBD (headers-first), blocks often arrive out of order from
        multiple peers.  Instead of treating out-of-order blocks as orphans
        (which breaks bootstrapping), we buffer them keyed by hash and
        drain the buffer sequentially after each successful connect.

        Perf: the block hash is computed from the 80-byte header only (cheap
        double-SHA256).  Full Python-side `Block.deserialize` is deferred to
        `_drain_block_buffer` where it runs inside `asyncio.to_thread`, so
        the event loop is not stalled by a ~1 MB per-block deser each time a
        peer delivers a block.  This is the primary bottleneck per py-spy
        (W13): every inbound block held the GIL-owning MainThread for the
        length of `Block.deserialize`, starving timeout handling, RPC, and
        peer message dispatch — including blocks already sitting in the OS
        socket buffer from other peers.
        """
        self._blk_received += 1
        try:
            payload = msg.payload
            if len(payload) < 80:
                self._blk_too_short += 1
                logger.error(f"Block payload too short from {peer.host}:{peer.port}")
                peer.adjust_score(-5)
                return

            # W95: feed the recent-block-size EMA used by _handle_timeouts.
            # Do this on every received block (including duplicates we're
            # about to drop below) so the signal tracks the true payload
            # distribution rather than just the unique-block subset.
            block_mb = len(payload) / (1024.0 * 1024.0)
            self._w95_block_mb_ema = (
                (1.0 - self._w95_block_mb_alpha) * self._w95_block_mb_ema
                + self._w95_block_mb_alpha * block_mb
            )

            # Compute block hash from the 80-byte header only.  This matches
            # wire / DB internal byte order used elsewhere in the codebase
            # (see `_header_to_block_hash`).
            block_hash = hashlib.sha256(
                hashlib.sha256(payload[:80]).digest()
            ).digest()

            # Was this delivery in response to one of our outstanding requests?
            # We sample this BEFORE clearing the in-flight entry so the
            # post-rollback duplicate suppression below can distinguish a
            # solicited redelivery (we still want it; the validated-header
            # queue includes its hash) from a genuinely-already-have-it
            # spontaneous duplicate.
            was_requested = block_hash in self.requested_blocks
            if was_requested:
                del self.requested_blocks[block_hash]
            self._block_request_peer.pop(block_hash, None)

            # Already have this block?  Skip duplicate ONLY if we did not
            # request it.  After a chainstate rollback, BLOCKS_CF still
            # contains the previously-stored bytes for blocks that have
            # since been disconnected from the active chain, so
            # `has_block_hash=True` does NOT mean "block is on chain".  If
            # the block is something we asked for, accept the bytes into
            # the buffer so the drain path can re-validate and re-connect
            # them — without this, after a rollback we would drop every
            # peer redelivery on the floor and the drain would wait
            # forever for a buffer entry that never arrives.
            if not was_requested and self.db.has_block_hash(block_hash):
                self._blk_duplicate += 1
                return

            # Permanently rejected on a prior validation pass?  Drop without
            # re-buffering and dock the redelivering peer.  Without this guard,
            # peer redeliveries of the same bad bytes spin the drain loop.
            if block_hash in self._perm_rejected_blocks:
                self._blk_perm_rejected_dropped += 1
                logger.debug(
                    f"Dropping perm-rejected block {block_hash.hex()[:16]}... "
                    f"redelivered from {peer.host}:{peer.port}"
                )
                peer.adjust_score(-5)
                return

            # G19c fTooFarAhead gate (Bitcoin Core validation.cpp:4325-4350):
            # Unrequested blocks claiming a height more than MIN_BLOCKS_TO_KEEP
            # (288) above the active tip are silently dropped.  Without this
            # gate a peer can fill _ibd_block_buffer with blocks at heights
            # millions above tip, wasting memory and CPU.
            # Only applied to unrequested blocks — requested blocks (those we
            # explicitly fetched via getdata) are always buffered regardless of
            # their position relative to tip, mirroring Core's `if (!fRequested)`
            # guard condition.
            if not was_requested:
                _, active_height = self.db.get_best_block()
                # Determine the claimed height from the validated-header queue.
                # Slot 0 is tip+1, slot 1 is tip+2, etc.
                claimed_height: int | None = None
                for _idx, (_bh, _) in enumerate(self._validated_headers):
                    if _bh == block_hash:
                        claimed_height = active_height + 1 + _idx
                        break
                if (
                    claimed_height is not None
                    and claimed_height > active_height + MIN_BLOCKS_TO_KEEP
                ):
                    logger.debug(
                        f"fTooFarAhead: dropping unrequested block "
                        f"{block_hash.hex()[:16]}... claimed_height={claimed_height} "
                        f"active_height={active_height} limit={active_height + MIN_BLOCKS_TO_KEEP} "
                        f"from {peer.host}:{peer.port}"
                    )
                    return

            # Buffer the raw payload (keyed by hash) for sequential
            # processing.  `None` sentinel means "not yet deserialized" —
            # the drainer will deserialize lazily in a worker thread when it
            # actually needs to validate/connect this block.
            # W101: asymmetric, head-reserving admission.  W100 made the
            # REQUEST side always re-fetch the head-of-window (tip+1..
            # tip+HEAD_OF_WINDOW, _request_next_blocks); this is its
            # RECEIVE-side complement.  The old flat `len < _max_ibd_buffer`
            # cap let the 256 in-flight far-ahead arrivals fill the buffer
            # (buffer_target 768 + max_in_flight 256 == _max_ibd_buffer 1024
            # exactly) leaving ZERO room to ADMIT tip+1, which the drain
            # (_drain_block_buffer_locked) needs in slot 0 to advance at all
            # -- the 946044 buffer-admission deadlock (W101).  Fix: reserve
            # HEAD_OF_WINDOW slots for the head-of-window so a contiguous-
            # from-tip block is ALWAYS admittable, evicting the FARTHEST-
            # height resident if at the hard cap.  Core never gates the
            # connect-frontier block on a receive buffer (it spills to disk);
            # this restores that invariant for our bounded RAM buffer.  Never
            # drop a head-ward block to keep a farther one (the W85 invariant).
            # HEAD_OF_WINDOW MUST match _request_next_blocks / _handle_timeouts
            # -- a divergence silently reclassifies tip+1 as far-ahead at one
            # site and re-opens the wedge.
            HEAD_OF_WINDOW = 8  # MUST match _request_next_blocks / _handle_timeouts
            buf_len = len(self._ibd_block_buffer)
            if buf_len < self._max_ibd_buffer - HEAD_OF_WINDOW:
                # Common case: ample room.  Admit anything (far-ahead or head).
                # No is-head probe -- the hot path stays free of
                # get_block_hash_by_height calls and scans.
                self._ibd_block_buffer[block_hash] = (None, payload)
                self._block_source_peer_addr[block_hash] = f"{peer.host}:{peer.port}"
                self._blk_buffered += 1
            else:
                # Near-full (top HEAD_OF_WINDOW slots): only the head-of-window
                # may use the reserved slots.  Build head_set with the SAME
                # cheap primitive _request_next_blocks / _handle_timeouts use --
                # get_block_hash_by_height(tip+1+i)==bh (returns None for
                # unconnected heights, NOT has_block_hash, so rollback-orphans
                # don't shadow the genuine head; the 938231 guard).  Guarded to
                # run ONLY when near-full, so the uncongested path never pays.
                _, _active_height = self.db.get_best_block()
                head_set: set[bytes] = set()
                for _i, (_bh, _) in enumerate(self._validated_headers):
                    if self.db.get_block_hash_by_height(_active_height + 1 + _i) == _bh:
                        continue
                    head_set.add(_bh)
                    if len(head_set) >= HEAD_OF_WINDOW:
                        break
                is_head = block_hash in head_set
                if is_head and buf_len < self._max_ibd_buffer:
                    # Head-of-window into one of the reserved slots.
                    self._ibd_block_buffer[block_hash] = (None, payload)
                    self._block_source_peer_addr[block_hash] = f"{peer.host}:{peer.port}"
                    self._blk_buffered += 1
                elif is_head:
                    # Hard cap AND this is the head-of-window: evict the
                    # FARTHEST-height resident far-ahead block to make room.
                    # Slot index in _validated_headers == height-above-tip
                    # (slot 0 == tip+1 by the anchored-queue invariant), so the
                    # resident with the LARGEST slot index is the farthest.
                    # Walk from the TAIL downward and take the first resident
                    # not in head_set -- O(distance from tail to first far-ahead
                    # resident), typically O(1).  The evicted block stays in
                    # _validated_headers and is re-fetchable later via the TAIL
                    # pass once the buffer drops below buffer_target, so eviction
                    # only costs a re-download of an already-speculative block --
                    # never a head-ward one (W82/W85-safe).
                    evict_hash: bytes | None = None
                    for _i in range(len(self._validated_headers) - 1, -1, -1):
                        _bh = self._validated_headers[_i][0]
                        if _bh in self._ibd_block_buffer and _bh not in head_set:
                            evict_hash = _bh
                            break
                    if evict_hash is not None:
                        del self._ibd_block_buffer[evict_hash]
                        self._block_source_peer_addr.pop(evict_hash, None)
                        self._blk_buffer_full += 1  # count the eviction-drop
                        self._ibd_block_buffer[block_hash] = (None, payload)
                        self._block_source_peer_addr[block_hash] = f"{peer.host}:{peer.port}"
                        self._blk_buffered += 1
                    else:
                        # No far-ahead resident to evict (buffer is ALL
                        # head-of-window) -- admit anyway.  The head set is
                        # bounded at HEAD_OF_WINDOW, so this can over-fill by at
                        # most HEAD_OF_WINDOW slots, and it IS the contiguous
                        # prefix so it drains immediately at the drain below.
                        self._ibd_block_buffer[block_hash] = (None, payload)
                        self._block_source_peer_addr[block_hash] = f"{peer.host}:{peer.port}"
                        self._blk_buffered += 1
                else:
                    # Far-ahead block while in the reserved band -- drop it.
                    # It is re-requestable via the TAIL pass and is NOT the
                    # block the drain is waiting for.
                    self._blk_buffer_full += 1
                    logger.debug(
                        f"IBD buffer near-full ({buf_len}/{self._max_ibd_buffer}, "
                        f"head reserve={HEAD_OF_WINDOW}), dropping far-ahead "
                        f"{block_hash.hex()[:16]}..."
                    )
                    return

            # Try to drain buffered blocks in chain order.
            connected = await self._drain_block_buffer()

            if connected > 0:
                # Advance download window after connecting blocks.
                await self._request_next_blocks()

        except Exception as e:
            self._blk_error += 1
            logger.error(f"Error handling block from {peer.host}:{peer.port}: {e}", exc_info=True)
            peer.adjust_score(-5)

    async def _drain_block_buffer(self) -> int:
        """Connect buffered blocks in chain order.

        Walks the validated header queue starting from the current tip,
        checking if the next expected block is in the buffer.  Connects
        as many sequential blocks as possible.

        Returns the number of blocks connected.
        """
        if self._drain_lock is None:
            self._drain_lock = asyncio.Lock()
        # If another drain task already holds the lock, skip this
        # invocation — that task will drain everything currently
        # buffered, so there is nothing for us to do.  Blocking on
        # acquire would queue up a redundant second pass that does no
        # useful work.
        if self._drain_lock.locked():
            return 0
        async with self._drain_lock:
            return await self._drain_block_buffer_locked()

    async def _drain_block_buffer_locked(self) -> int:
        connected = 0
        # W91: record drain entry — idle since previous exit, and buffer
        # size at the moment we start draining.
        _w91_entry_ns = time.perf_counter_ns()
        self._w91_drain_entries += 1
        self._w91_buffer_on_entry_sum += len(self._ibd_block_buffer)
        if self._w91_last_drain_exit_perf_ns:
            idle_ns = _w91_entry_ns - self._w91_last_drain_exit_perf_ns
            if idle_ns > 0:
                self._w91_drain_idle_sum_ns += idle_ns
                if idle_ns > self._w91_drain_idle_max_ns:
                    self._w91_drain_idle_max_ns = idle_ns
        current_hash, current_height = self.db.get_best_block()

        # Sanity-check the queue invariant before draining.  If
        # ``_validated_headers[0]`` does not extend the active chain tip
        # (which can happen after a chainstate rollback or reorg between
        # when the queue was built and now), drop the entire queue and
        # let the next sync_loop tick rebuild it.  We deliberately do NOT
        # use ``has_block_hash`` to "skip already-connected" headers: that
        # probe returns True for any stored block, including ones
        # disconnected from the active chain by a rollback, and the skip
        # silently advances the drain pointer past orphaned slots — that
        # is the 938231 wedge from 2026-05-02.  Slot 0 is always tip+1
        # by the invariant we now enforce.
        if not self._queue_anchored_to_tip():
            logger.warning(
                "[slot-misalign] validated_headers no longer anchors to tip "
                "%s — dropping queue (%d entries) for fresh resync",
                current_hash.hex()[:16] if current_hash else "?",
                len(self._validated_headers),
            )
            self._validated_headers.clear()
            self._ibd_block_buffer.clear()
            self.requested_blocks.clear()
            self._block_request_peer.clear()
            self._block_source_peer_addr.clear()
            # Telemetry-only request→connect latency dict; clear with the
            # sibling maps so a bulk queue-drop doesn't orphan its entries.
            self._w77_first_request_time.clear()
            self._w77_first_request_order.clear()
            self._block_request_attempts.clear()
            self._header_sync_peer = None
            self._header_sync_time = 0.0
            self._w91_last_drain_exit_perf_ns = time.perf_counter_ns()
            return 0
        header_idx = 0

        while header_idx < len(self._validated_headers):
            next_hash, _ = self._validated_headers[header_idx]

            # Is the next block in our buffer?
            if next_hash not in self._ibd_block_buffer:
                break  # need to wait for download

            block, raw_payload = self._ibd_block_buffer.pop(next_hash)

            # Lazy-deserialize: `handle_block` defers the ~1 MB Python-side
            # `Block.deserialize` here so it runs in a worker thread and
            # does not stall the event loop on block arrival.  Sentinel
            # `None` means "not yet deserialized".
            deserialize_ns = 0
            if block is None:
                t0 = time.perf_counter_ns()
                try:
                    block = await asyncio.to_thread(Block.deserialize, raw_payload)
                except Exception as e:
                    logger.warning(
                        f"Failed to deserialize buffered block "
                        f"{next_hash.hex()[:16]}...: {e}"
                    )
                    # Deserialization failure is unrecoverable for this block —
                    # the bytes are corrupt.  Drop it and let the timeout handler
                    # re-fetch from a different peer.
                    break
                deserialize_ns = time.perf_counter_ns() - t0

            # Validate and connect in a thread to avoid blocking the event
            # loop.  Individual block validations at higher heights can take
            # seconds (Rust FFI + DB writes).  Running them in a thread lets
            # the event loop service RPC requests and peer messages meanwhile.
            new_height = current_height + 1

            # Defensive BIP34 height-vs-slot sanity check.
            # Decode the BIP34-encoded height from the coinbase scriptSig and
            # confirm it matches the slot we're about to validate this block
            # against.  A mismatch means our `_validated_headers` queue is
            # misaligned (slot N is holding a header whose block-hash maps
            # to a different chain height than tip+1).  This is the live
            # 938231 vs 938349 wedge: peers correctly delivered the block
            # whose hash sat at slot 0 in our queue, but that hash was the
            # NEXT chain-tip after a disconnected old chain — not tip+1.
            # When this fires, the slot index is corrupt — drop the
            # validated_headers queue and request fresh headers rather than
            # spinning the drain loop and starving the connect path.
            if self._coinbase_height_mismatch(block, new_height):
                self._handle_misaligned_block(next_hash, new_height, block)
                break

            t_val = time.perf_counter_ns()

            # P2P block acceptance pipeline — Core ProcessNewBlock parity.
            # Entry point 3 of 5 (wave-29 audit).  The validate→connect
            # sequence below is the canonical IBD path.  RPC entry points
            # (rpc_submitblock, rpc_submitblockbatch, rpc_generatetoaddress)
            # use the unified ``accept_block`` helper in rpc.py which mirrors
            # this same pipeline.  The Rust import-blocks path
            # (import_blocks_from_file) was updated alongside this commit.
            #
            # B3 Stage 1: Rust validate fast path (default-on as of the
            # W90/W91 soak, 2026-04-22).
            #
            # Two env-flag modes:
            # - OUROBOROS_VALIDATE_CROSS_CHECK=1 → run BOTH Rust and Python,
            #   compare results, log mismatches, trust Python.  Soak window.
            # - OUROBOROS_DISABLE_RUST_VALIDATE=1 → force the Python
            #   validator (emergency opt-out; retained for diagnostics).
            # - otherwise (default) → run Rust only, fall back to Python
            #   on unexpected errors.  Steady state.
            #
            # Both Rust-using paths are gated on can_skip_scripts_for_block
            # (so below assumevalid checkpoint only); above the checkpoint,
            # Python's script verification path is kept regardless of flags.
            cross_check = os.environ.get("OUROBOROS_VALIDATE_CROSS_CHECK") == "1"
            route_only = (
                not cross_check
                and os.environ.get("OUROBOROS_DISABLE_RUST_VALIDATE") != "1"
            )
            rust_available = (
                _has_sync_module
                and hasattr(self.db, "validate_block_from_bytes")
            )
            network = (
                self.peer_manager.network
                if hasattr(self.peer_manager, "network")
                else "mainnet"
            )
            skip_scripts = False
            if (cross_check or route_only) and rust_available:
                try:
                    skip_scripts = _sync_module.can_skip_scripts_for_block(
                        network, new_height, next_hash
                    )
                except Exception:
                    skip_scripts = False

            async def _run_rust() -> tuple[bool, str]:
                try:
                    await asyncio.to_thread(
                        self.db.validate_block_from_bytes,
                        raw_payload,
                        new_height - 1,
                        True,
                        network,
                    )
                    return True, ""
                except ValueError as e:
                    return False, str(e)

            async def _run_python() -> tuple[bool, str]:
                return await asyncio.to_thread(
                    self.validator.validate_block,
                    block,
                    known_height=new_height,
                )

            validated_via_rust = False
            if cross_check and rust_available and skip_scripts:
                try:
                    rust_result = await _run_rust()
                except Exception as e:
                    logger.warning(
                        f"Rust validate raised unexpectedly at height "
                        f"{new_height}: {e}; skipping cross-check for this block"
                    )
                    rust_result = None
                python_result = await _run_python()
                valid, error = python_result
                if rust_result is not None:
                    # Match on the accept/reject boolean only. Rust and
                    # Python often reject invalid blocks for different
                    # diagnostic reasons (e.g. "Previous block hash
                    # mismatch" vs "Previous block not found") — that is
                    # not a consensus disagreement. The strict tuple-eq
                    # check flagged those as mismatches during initial
                    # soak, drowning out real (True, False) / (False,
                    # True) divergences.
                    matched = rust_result[0] == python_result[0]
                    _record_cross_check(
                        matched,
                        height=new_height,
                        rust_result=rust_result,
                        python_result=python_result,
                    )
                    if not matched:
                        logger.error(
                            f"B3 cross-check MISMATCH at height {new_height}: "
                            f"rust={rust_result} python={python_result}"
                        )
                        # B3 diagnostic: when Python rejected with
                        # "Input not found: <txid>:<vout>" but Rust accepted,
                        # re-probe the outpoint directly against the shared
                        # DB to determine whether the two sides actually see
                        # different UTXO state (a real Rust vs Python DB read
                        # divergence) or whether the asymmetry is in the
                        # intra-block view construction (one side finds it in
                        # `extras`/`intra_block_utxos`, the other doesn't).
                        # Also check whether the outpoint is created by an
                        # earlier tx in the same block — if so, the divergence
                        # is intra-block-view, not DB.
                        try:
                            perr = python_result[1] or ""
                            marker = "Input not found: "
                            if marker in perr:
                                # Extract failing tx index from the "Transaction N invalid:" prefix
                                failing_tx_idx: int | None = None
                                try:
                                    m = perr.split("Transaction ", 1)[1]
                                    failing_tx_idx = int(m.split(" ", 1)[0])
                                except Exception:
                                    pass
                                tail = perr[perr.rindex(marker) + len(marker):]
                                txhex, _, vout_s = tail.partition(":")
                                vout_s = vout_s.split(" ")[0].split(",")[0]
                                op_txid = bytes.fromhex(txhex.strip())
                                op_vout = int(vout_s.strip())
                                probe = self.db.get_utxo(op_txid, op_vout)
                                created_in_block: int | None = None
                                for ti, btx in enumerate(block.transactions):
                                    if btx.get_txid() == op_txid:
                                        if op_vout < len(btx.outputs):
                                            created_in_block = ti
                                        break
                                logger.error(
                                    f"B3 mismatch probe h={new_height} "
                                    f"outpoint={txhex}:{op_vout} "
                                    f"db_get_utxo={'HIT' if probe else 'MISS'} "
                                    f"created_by_block_tx_index={created_in_block} "
                                    f"n_block_tx={len(block.transactions)} "
                                    f"failing_tx_idx={failing_tx_idx}"
                                )
                                # Re-run Rust immediately on the same bytes.
                                # If Rust now rejects, this is timing/state-
                                # change (another block applied between the
                                # two cross-check calls). If Rust still
                                # accepts, the divergence is pure logic.
                                try:
                                    self.db.validate_block_from_bytes(
                                        raw_payload, new_height - 1, True, network
                                    )
                                    rust_reprobe = "ACCEPT"
                                except ValueError as e:
                                    rust_reprobe = f"REJECT:{str(e)[:80]}"
                                # Probe every input of the failing tx to see
                                # how many resolve via DB (not yet checking
                                # intra-block, since tx idx is known).
                                db_hits = db_misses = intra_hits = 0
                                if failing_tx_idx is not None and 0 <= failing_tx_idx < len(block.transactions):
                                    ftx = block.transactions[failing_tx_idx]
                                    intra: dict[tuple[bytes, int], int] = {}
                                    for ti in range(failing_tx_idx):
                                        ptx = block.transactions[ti]
                                        ptxid = ptx.get_txid()
                                        for vo in range(len(ptx.outputs)):
                                            intra[(ptxid, vo)] = ti
                                    for tin in ftx.inputs:
                                        u = self.db.get_utxo(tin.prev_txid, tin.prev_vout)
                                        if u is not None:
                                            db_hits += 1
                                        elif (tin.prev_txid, tin.prev_vout) in intra:
                                            intra_hits += 1
                                        else:
                                            db_misses += 1
                                logger.error(
                                    f"B3 mismatch probe2 h={new_height} "
                                    f"failing_tx={failing_tx_idx} "
                                    f"n_inputs={len(ftx.inputs) if failing_tx_idx is not None else '?'} "
                                    f"db_hits={db_hits} intra_hits={intra_hits} "
                                    f"db_misses={db_misses} rust_reprobe={rust_reprobe}"
                                )
                        except Exception as probe_err:
                            logger.debug(
                                f"B3 mismatch probe failed at "
                                f"h={new_height}: {probe_err}"
                            )
                    elif rust_result[1] != python_result[1]:
                        logger.debug(
                            f"B3 cross-check agree (different error text) "
                            f"at height {new_height}: "
                            f"rust={rust_result[1][:80]!r} "
                            f"python={python_result[1][:80]!r}"
                        )
            elif route_only and rust_available and skip_scripts:
                try:
                    valid, error = await _run_rust()
                    validated_via_rust = True
                except Exception as e:
                    logger.warning(
                        f"Rust validate_block_from_bytes raised "
                        f"unexpectedly at height {new_height}: {e}; "
                        f"falling back to Python validator"
                    )

            if not validated_via_rust and not cross_check:
                valid, error = await _run_python()
            validate_ns = time.perf_counter_ns() - t_val
            if not valid:
                self._blk_validate_rejected += 1
                logger.warning(
                    f"✗ Invalid block at height {new_height}: {error}"
                )
                # "Previous block not found" is a transient ordering error —
                # the block data is good but the parent is not yet in the DB.
                # Put the block back in the buffer so the next drain attempt
                # can try again once the parent has been connected.
                # Any other validation error is a permanent failure: the block
                # bytes are bogus (sent by a misbehaving peer).  Drop it so
                # the timeout handler re-fetches from a different peer, and
                # add the hash to ``_perm_rejected_blocks`` so subsequent
                # redeliveries from any peer get dropped at handle_block
                # without a fresh deserialize / validate cycle.
                if error == "Previous block not found":
                    self._ibd_block_buffer[next_hash] = (block, raw_payload)
                else:
                    self._mark_perm_rejected(next_hash)
                    # G16/G17 (W99): Bitcoin Core's ProcessNewBlock calls
                    # Misbehaving(100) for BLOCK_MUTATED (merkle tree with
                    # duplicate txids) and BLOCK_INVALID_HEADER (bad PoW,
                    # bad prev-hash, bad bits, etc.).  Score the delivering
                    # peer so the ban manager can disconnect and ban it.
                    # Ref: net_processing.cpp — ProcessNewBlock path.
                    _misbehav_errors = ("Invalid merkle root", "Invalid header")
                    if error.startswith(_misbehav_errors):
                        _src_addr = self._block_source_peer_addr.get(next_hash)
                        if _src_addr and hasattr(self.peer_manager, "misbehaving"):
                            from ouroboros.banman import SCORE_INVALID_BLOCK
                            self.peer_manager.misbehaving(
                                _src_addr, SCORE_INVALID_BLOCK,
                                f"BLOCK_MUTATED/INVALID_HEADER: {error[:80]}"
                            )
                    self._block_source_peer_addr.pop(next_hash, None)
                break

            # Clear peer-address tracking for successfully accepted block
            self._block_source_peer_addr.pop(next_hash, None)

            # Connect block
            t_con = time.perf_counter_ns()
            try:
                if hasattr(self.db, 'connect_block_from_bytes'):
                    await asyncio.to_thread(
                        self.db.connect_block_from_bytes, raw_payload, new_height
                    )
                else:
                    await asyncio.to_thread(self.validator.apply_block, block)
            except Exception as e:
                self._blk_connect_failed += 1
                logger.error(f"Failed to connect block at height {new_height}: {e}")
                # DB connect failure is also transient (e.g. chain-tip mismatch
                # due to a concurrent update).  Put the block back so we retry.
                self._ibd_block_buffer[next_hash] = (block, raw_payload)
                break
            connect_ns = time.perf_counter_ns() - t_con

            self._w76_record_phases(deserialize_ns, validate_ns, connect_ns)
            self._w90_record_validate(
                validate_ns=validate_ns,
                via_rust=validated_via_rust,
                skip_scripts=skip_scripts,
                tx_count=len(block.transactions) if block is not None else 0,
                height=new_height,
            )
            self._w91_record_connect(deserialize_ns, validate_ns, connect_ns)

            connected += 1
            current_height = new_height
            header_idx += 1
            self._blk_connected += 1
            self._last_tip_advance = time.time()

            self._w77_record_connect(next_hash, self._last_tip_advance)

            # Feed fee estimator
            if self.fee_estimator is not None:
                try:
                    self.fee_estimator.process_block(block, new_height, self.mempool)
                except Exception:
                    pass

            # BIP 157/158 — index the basic filter for this block once it
            # is canonically connected.  Off-thread because filter
            # construction touches the DB (prevout lookups) and is tens of
            # ms per block; we don't want to gate the connect loop on it.
            # Errors here are non-fatal: an index fault must never stall
            # IBD.  TODO(BIP157): batch-flush the underlying file writes
            # rather than open(...wb) per block; reorg-aware rollback.
            if self.block_filter_index is not None:
                try:
                    await asyncio.to_thread(
                        self.block_filter_index.add_block,
                        block,
                        new_height,
                        self.db,
                    )
                except Exception as e:
                    logger.warning(
                        f"block_filter_index.add_block failed at "
                        f"height {new_height}: {e}"
                    )

            # Remove confirmed txs from mempool
            if self.mempool is not None:
                self.mempool.remove_block_transactions(block)

            if self._zmq_publisher:
                self._zmq_publisher.notify_block(block)

            # Log progress every 1000 blocks
            if new_height % 1000 == 0 or connected == 1:
                logger.info(
                    f"✓ Block {new_height} connected "
                    f"(buffer={len(self._ibd_block_buffer)}, "
                    f"in-flight={len(self.requested_blocks)})"
                )

            # Yield to the event loop after each block so that RPC handlers,
            # peer message processing, and other coroutines are not starved
            # during IBD.  Without this, the while loop holds the event loop
            # for the entire drain (potentially hundreds of blocks), causing
            # multi-second RPC latency spikes.
            await asyncio.sleep(0)

        # Prune connected headers to prevent unbounded growth.
        # `connected` blocks were popped from slot 0 in chain order, so the
        # first `connected` entries in _validated_headers are the ones we
        # just stored.  Drop them.  We deliberately do NOT use
        # has_block_hash to drive pruning: post-rollback BLOCKS_CF still
        # contains orphaned blocks, and a hash-based prune would silently
        # drop slots whose blocks are not on the active chain — masking
        # the slot-misalignment wedge instead of letting the anchor check
        # at the next drain entry detect and recover.
        if connected > 0:
            self._validated_headers = self._validated_headers[connected:]

        # W91: record drain exit.  No-progress drains (connected==0)
        # are counted separately — they indicate the drain woke up but
        # the next-expected block wasn't buffered.  Exit timestamp
        # feeds into the next drain's idle measurement.
        if connected == 0:
            self._w91_drain_noprogress += 1
        self._w91_last_drain_exit_perf_ns = time.perf_counter_ns()

        return connected

    def _header_to_block_hash(self, header) -> bytes:
        header_bytes = header.serialize()
        block_hash_raw = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
        return block_hash_raw  # internal byte order — matches DB and wire

    @staticmethod
    def _bits_to_target(bits: int) -> int:
        """Decode Bitcoin's compact 'bits' representation into a 256-bit target.

        Mirrors ``ouroboros.validation._bits_to_target`` (and Core's
        ``arith_uint256::SetCompact``) — duplicated here to keep
        ``handle_headers`` import-free of the heavyweight validator
        module on the hot header-receive path.
        """
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if mantissa == 0:
            return 0
        if exponent <= 3:
            return mantissa >> (8 * (3 - exponent))
        return mantissa << (8 * (exponent - 3))

    @classmethod
    def _header_meets_pow(cls, header) -> bool:
        """Return True iff ``double-SHA256(header)`` interpreted as a
        little-endian uint256 is ``<=`` the target encoded in
        ``header.bits``.

        This is the per-header PoW gate that Bitcoin Core enforces
        before accepting headers in ``CheckBlockHeader`` — without it,
        a peer can flood low-difficulty-claimed headers whose hashes
        do NOT actually meet the claimed target, exhausting our
        validated-header queue (50K cap) cheaply.  Pairs with the
        Rust ``HeadersSyncState`` presync state machine which
        accumulates work from claimed bits but does not itself
        verify hash≤target on each header.

        Ref: bitcoin/src/pow.cpp ``CheckProofOfWork``;
        CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part2.md
        RED finding #1.
        """
        try:
            header_bytes = header.serialize()
            block_hash = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
            hash_as_int = int.from_bytes(block_hash, "little")
            target = cls._bits_to_target(int(header.bits))
            if target <= 0:
                return False
            return hash_as_int <= target
        except Exception:
            # Malformed bits or serialization → treat as failed PoW.
            return False

    def _get_presync_state(self, peer: Peer):
        """Lazily create / fetch the Rust ``PyHeadersSyncState`` for *peer*.

        Returns ``None`` if the Rust ``sync`` module does not export the
        anti-DoS state machine (older builds / test stubs).  In that
        case the caller still gets the per-header PoW gate +
        chain-continuity checks; only the presync commitment-tracking
        defense-in-depth is skipped.

        State is keyed by ``(peer.host, peer.port)`` and reused across
        successive ``headers`` messages from the same peer so cumulative
        work + commitments accumulate correctly (Core's
        ``HeadersSyncState`` is per-peer).
        """
        if not _has_sync_module:
            return None
        cls = getattr(_sync_module, "PyHeadersSyncState", None)
        if cls is None:
            return None  # Test stub or older build without presync exposed.
        try:
            host = getattr(peer, "host", None)
            port = getattr(peer, "port", None)
            key = (host, port)
        except Exception:
            return None
        state = self._presync_states.get(key)
        if state is not None:
            return state
        # Build a fresh state.
        # chain_start = our current best block (genesis fork point).
        # chain_start_height / chain_start_bits are now forwarded so the
        # Rust state machine initialises commitment slots and difficulty
        # checks correctly when we are not syncing from genesis.
        # Bug 1/2/3/4/5 fix: pass height + bits, not just hash + time.
        # Core: HeadersSyncState ctor (headerssync.cpp:17-46).
        try:
            best_hash, best_height = self.db.get_best_block()
        except Exception:
            best_hash = b"\x00" * 32
            best_height = 0
        if not isinstance(best_hash, (bytes, bytearray)) or len(best_hash) != 32:
            best_hash = b"\x00" * 32
            best_height = 0
        # Retrieve the nBits stored for the tip header so the presync
        # machine can seed its prev_bits correctly.
        best_bits: int = 0
        network = self.peer_manager.network if hasattr(self.peer_manager, "network") else "mainnet"
        try:
            if hasattr(self.db, "get_block_bits"):
                best_bits = int(self.db.get_block_bits(best_hash) or 0)
            elif hasattr(self.db, "get_block_metadata_by_hash"):
                meta = self.db.get_block_metadata_by_hash(best_hash)
                best_bits = int(getattr(meta, "bits", 0) or 0) if meta else 0
        except Exception:
            best_bits = 0
        # SNAPSHOT BOOTSTRAP: after an assumeUTXO import the tip header's nBits
        # is not reachable via the metadata lookups above — the import / base-
        # index persist writes only height + chainwork + timestamp
        # (store_block_metadata_persistent has no bits field), and the Python
        # BlockchainDatabase exposes no get_block_bits, so best_bits resolves to
        # 0 for the snapshot base AND for the first blocks connected above it.
        # Seeding the presync state with prev_bits=0 makes the Rust
        # HeadersSyncState reject the FIRST real headers batch with "Invalid
        # difficulty transition at height tip+1: 0 -> <real bits>" (a non-
        # boundary height demands unchanged bits, and 0 != <real bits>),
        # starving the block downloader of headers and wedging forward-sync a
        # few blocks above the base.  Bitcoin Core never hits this: its
        # HeadersSyncState ctor seeds chain_start from a real CBlockIndex
        # carrying the tip's nBits (headerssync.cpp:17-46).
        #
        # Recover the real prev_bits, in priority order:
        #   1. the tip block's own header bits (offset 72 of the stored bytes /
        #      Block.bits) — works for any block connected above the base that
        #      has a body (e.g. tip 944185 on a restart);
        #   2. the assumeUTXO base_header (offset 72) keyed by the tip hash —
        #      needed when the tip IS the snapshot base (944183), which has no
        #      block body in BLOCKS_CF, only the persisted base header.
        # Snapshot-bootstrap-scoped (only fires when best_bits would otherwise
        # be 0); default-preserving for normal sync, where best_bits already
        # resolves to the tip header's real value above.
        if best_bits == 0:
            recovered_bits = 0
            recovered_src = ""
            # 1. Tip block header bits (block above the base, has a body).
            try:
                if hasattr(self.db, "get_block_bytes"):
                    raw = self.db.get_block_bytes(bytes(best_hash))
                    if raw is not None and len(raw) >= 80:
                        recovered_bits = int.from_bytes(raw[72:76], "little")
                        recovered_src = "tip block header"
                if recovered_bits == 0 and hasattr(self.db, "get_block"):
                    blk = self.db.get_block(bytes(best_hash))
                    b = int(getattr(blk, "bits", 0) or 0) if blk else 0
                    if b > 0:
                        recovered_bits = b
                        recovered_src = "tip Block.bits"
            except Exception:
                recovered_bits = 0
            # 2. assumeUTXO base_header (tip == snapshot base, no body).
            if recovered_bits == 0:
                try:
                    from ouroboros.snapshot import get_assumeutxo_by_hash
                    au = get_assumeutxo_by_hash(network, bytes(best_hash))
                    if au is not None and au.base_header is not None \
                            and len(au.base_header) == 80:
                        b = int.from_bytes(au.base_header[72:76], "little")
                        if b > 0:
                            recovered_bits = b
                            recovered_src = "assumeUTXO base header"
                except Exception:
                    recovered_bits = 0
            if recovered_bits > 0:
                best_bits = recovered_bits
                logger.info(
                    "[snapshot] Seeded presync prev_bits from %s: height=%d "
                    "bits=%#010x (no nBits in base-index metadata)",
                    recovered_src, int(best_height), recovered_bits,
                )
        try:
            mtp = int(self.db.get_median_time_past()) if hasattr(self.db, "get_median_time_past") else 0
        except Exception:
            mtp = 0
        if mtp <= 0:
            mtp = int(time.time())
        try:
            state = cls(
                network,
                bytes(best_hash),
                int(mtp),
                int(best_height),
                int(best_bits),
            )
        except Exception as e:
            logger.debug(f"PyHeadersSyncState init failed ({network}): {e}")
            return None
        self._presync_states[key] = state
        return state

    def _drop_presync_state(self, peer: Peer):
        """Forget any presync state associated with *peer*.

        Called after a presync failure (the state has self-finalized to
        ``Final``) or when the peer disconnects.  Prevents stale state
        from poisoning a subsequent retry against a different peer.
        """
        try:
            host = getattr(peer, "host", None)
            port = getattr(peer, "port", None)
            self._presync_states.pop((host, port), None)
        except Exception:
            pass

    def _peer_key(self, peer: Peer) -> str:
        """Stable lookup key for the per-peer unconnecting-headers map.

        Uses the same ``host:port`` form the misbehavior path passes to
        ``peer_manager.misbehaving``.
        """
        host = getattr(peer, "host", "?")
        port = getattr(peer, "port", "?")
        return f"{host}:{port}"

    def _note_unconnecting_headers(self, peer: Peer) -> bool:
        """Increment the per-peer unconnecting-headers counter for *peer*.

        Returns ``True`` if the counter has exceeded
        ``_MAX_NUM_UNCONNECTING_HEADERS_MSGS`` (caller MUST disconnect /
        misbehavior-score the peer); returns ``False`` to indicate the
        counter is still under the bound.  Mirrors Bitcoin Core's
        ``nUnconnectingHeaders`` increment in
        ``net_processing.cpp::ProcessHeadersMessage``.
        """
        key = self._peer_key(peer)
        next_count = self._unconnecting_headers_count.get(key, 0) + 1
        self._unconnecting_headers_count[key] = next_count
        return next_count > _MAX_NUM_UNCONNECTING_HEADERS_MSGS

    def _reset_unconnecting_headers(self, peer: Peer) -> None:
        """Reset the unconnecting-headers counter for *peer*.

        Called on every successful connecting headers batch (Core's
        ``nUnconnectingHeaders = 0`` in the success path) and after
        the threshold-exceeded ban path so a re-connect under the
        same address starts fresh.
        """
        self._unconnecting_headers_count.pop(self._peer_key(peer), None)

    def _unconnecting_headers_count_for(self, peer: Peer) -> int:
        """Read the per-peer counter (used by tests)."""
        return self._unconnecting_headers_count.get(self._peer_key(peer), 0)

    @staticmethod
    def _bits_to_work(bits: int) -> int:
        """Compute the proof-of-work contributed by a single block with *bits*.

        work = 2^256 // (target + 1)

        Mirrors the accumulation formula in database.py and Bitcoin Core's
        ``GetBlockProof`` in ``chain.cpp``.  Used to check per-batch
        cumulative work against ``nMinimumChainWork`` (G8 gate).
        """
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if mantissa == 0:
            return 0
        if exponent <= 3:
            target = mantissa >> (8 * (3 - exponent))
        else:
            target = mantissa << (8 * (exponent - 3))
        if target <= 0:
            return 0
        return (2 ** 256) // (target + 1)

    def _snapshot_chainwork_offset(self) -> int:
        """Cached assumeUTXO chainwork correction offset for the G8 gate.

        A datadir bootstrapped from an assumeUTXO snapshot before the
        snapshot loader persisted the snapshot block's BlockMetadata has
        every post-snapshot block's stored chainwork accumulated from 0.
        ``get_chainwork_by_height`` therefore returns a value ~32x below
        the true cumulative work, so the raw DB-tip base understates the
        chain and the G8 nMinimumChainWork gate rejects every honest
        mainnet headers batch (the too-little-chainwork brick,
        2026-05-19).  This returns the canonical snapshot-height chainwork
        to add back; it returns 0 for a correctly built datadir.

        The result is cached: detection reads the DB once, and the value
        is stable for the process lifetime (the snapshot height does not
        change).  Mirrors ``Node._chainwork_snapshot_offset`` so the RPC
        chainwork display and this gate agree on the corrected total.
        """
        if not hasattr(self, "_snapshot_offset_cache"):
            from ouroboros.snapshot import detect_snapshot_chainwork_offset
            network = (
                self.peer_manager.network
                if hasattr(self.peer_manager, "network")
                else "mainnet"
            )
            self._snapshot_offset_cache = detect_snapshot_chainwork_offset(
                self.db, network
            )
        return self._snapshot_offset_cache

    async def handle_headers(self, msg: NetworkMessage, peer: Peer, *, min_pow_checked: bool = True):
        """Handle headers message — headers-first sync.

        Validates that received headers form a chain connecting to our
        current tip (or to the end of already-validated headers), then
        queues them for block download in a limited window.  This mirrors
        Bitcoin Core's approach in net_processing.cpp where block data is
        only requested after headers have been validated and connected.

        ``min_pow_checked`` mirrors Bitcoin Core's ``min_pow_checked`` parameter
        on ``AcceptBlockHeader`` / ``ProcessNewBlockHeaders``
        (validation.cpp:4186, 4242).  When False (raw P2P headers from a peer
        that has NOT been cleared by the PRESYNC state machine), this function
        computes the TOTAL chain work of the candidate chain — the cumulative
        work already stored at our DB tip PLUS the work of every queued header
        — and rejects the batch with ``too-little-chainwork`` if that total
        falls below ``nMinimumChainWork``.  The base term is essential: without
        it the check measures only the in-flight header window and rejects
        every batch once the node is past genesis.  When True (PRESYNC or
        trusted paths), the check is skipped.  Default is True for
        backward-compat with internal callers.

        Core canonical: validation.cpp:4229
            if (!min_pow_checked) return state.Invalid(BLOCK_HEADER_LOW_WORK,
                                                       "too-little-chainwork");
        """
        try:
            headers_msg = HeadersMessage.from_payload(msg.payload)

            if not headers_msg.headers:
                return

            logger.info(f"Received {len(headers_msg.headers)} headers from {peer.host}:{peer.port}")

            # Throttle header accumulation: if we already have a huge backlog
            # of validated headers waiting for block download, skip processing
            # more until we catch up.  This prevents unbounded memory growth
            # and keeps the set-dedup cost manageable.
            _MAX_HEADER_QUEUE = 50_000
            if len(self._validated_headers) > _MAX_HEADER_QUEUE:
                logger.debug(
                    f"Header queue at {len(self._validated_headers)}, "
                    f"skipping batch until blocks catch up"
                )
                return

            # Determine expected prev_hash: either last validated header or our DB tip.
            if self._validated_headers:
                expected_prev = self._validated_headers[-1][0]  # hash of last queued header
            else:
                best_hash, _ = self.db.get_best_block()
                expected_prev = best_hash

            accepted = 0
            # Headers that pass PoW + chain continuity in this batch and
            # therefore should be fed to the Rust ``HeadersSyncState``
            # presync state machine for commitment tracking.  Collected
            # here so we hand them to the state machine in one call
            # after the loop, matching Core's batch semantics.
            presync_feed: list = []
            # Build the known-hash set ONCE before the loop instead of
            # rebuilding it for every header.  With 200K+ queued headers
            # this was O(n*m) and burned 97% CPU, starving RPC.
            known_hashes = {h for h, _ in self._validated_headers}
            for header in headers_msg.headers:
                block_hash = self._header_to_block_hash(header)

                # Skip duplicates already in our validated queue.  This is
                # safe because such hashes were chain-validated when first
                # appended; advancing expected_prev preserves slot ordering.
                if block_hash in known_hashes:
                    expected_prev = block_hash
                    continue

                # Per-header PoW gate (BIP-130 anti-DoS).  Pre-2026-05-06
                # this loop only checked chain continuity, letting a peer
                # flood our 50K-slot queue with valid-prev forged-PoW
                # headers (audit RED #1).  We now require
                # ``double-SHA256(header) <= target(bits)`` before append.
                # Mirrors Bitcoin Core's CheckBlockHeader sequence.
                if not self._header_meets_pow(header):
                    self._headers_pow_rejected += 1
                    logger.warning(
                        f"Header {block_hash.hex()[:16]}... fails PoW "
                        f"(bits=0x{int(header.bits):08x}) from "
                        f"{peer.host}:{peer.port} — dropping batch"
                    )
                    # Treat as misbehavior: a peer that sends a header
                    # whose hash does not meet its claimed target is
                    # either attacking or corrupt.  Discard the rest of
                    # this batch and tell the peer manager.
                    peer.adjust_score(-20)
                    if hasattr(self.peer_manager, "misbehaving"):
                        addr = f"{peer.host}:{peer.port}"
                        self.peer_manager.misbehaving(
                            addr, 100, "header fails PoW (hash > target)"
                        )
                    self._drop_presync_state(peer)
                    return

                # NOTE: do NOT skip on `db.has_block_hash(block_hash)` here.
                # `BLOCKS_CF` retains every block we have ever received — it
                # is NOT pruned to the active chain when a block is
                # disconnected (e.g. by a `dumptxoutset` rollback or a reorg).
                # Skipping orphaned-but-stored headers and advancing
                # expected_prev along the OLD chain causes _validated_headers
                # slot 0 to become a header several blocks past our actual
                # tip: when block download then proceeds, the peer (correctly)
                # delivers a block whose BIP34 height does not match the slot
                # we requested it for, and validation rejects it with
                # "Invalid coinbase" forever.  See the 938231 vs 938349 wedge
                # in /data/nvme1/hashhog-mainnet/logs/ouroboros.log on
                # 2026-05-02 for the live manifestation.  Chain-prev
                # validation below catches all the cases the old skip was
                # papering over.

                # Validate chain continuity: header must extend expected_prev.
                header_prev = header.prev_blockhash if hasattr(header, 'prev_blockhash') else None
                if header_prev != expected_prev:
                    logger.warning(
                        f"Header {block_hash.hex()[:16]}... does not connect "
                        f"(expected prev {expected_prev.hex()[:16]}..., "
                        f"got {header_prev.hex()[:16] if header_prev else 'None'}...) — "
                        f"dropping remaining {len(headers_msg.headers) - accepted} headers"
                    )
                    # Core-parity unconnecting-headers counter: when the
                    # FIRST header of the batch fails the chain-continuity
                    # check (accepted == 0), this is the
                    # ``nUnconnectingHeaders`` case in
                    # net_processing.cpp::ProcessHeadersMessage.
                    # Tolerate up to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10
                    # successive misses before banning the peer.  Pre-fix,
                    # ouroboros silently ``break``ed with no penalty; see
                    # CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
                    # (Pattern B).
                    if accepted == 0:
                        if self._note_unconnecting_headers(peer):
                            addr = f"{peer.host}:{peer.port}"
                            logger.warning(
                                f"Peer {addr} exceeded "
                                f"MAX_NUM_UNCONNECTING_HEADERS_MSGS="
                                f"{_MAX_NUM_UNCONNECTING_HEADERS_MSGS}, "
                                f"misbehaving + dropping presync state"
                            )
                            peer.adjust_score(-20)
                            if hasattr(self.peer_manager, "misbehaving"):
                                self.peer_manager.misbehaving(
                                    addr, 20, "too many unconnecting headers"
                                )
                            self._reset_unconnecting_headers(peer)
                            self._drop_presync_state(peer)
                    break

                self._validated_headers.append((block_hash, header))
                known_hashes.add(block_hash)
                expected_prev = block_hash
                accepted += 1
                presync_feed.append(header)

            # G8 — nMinimumChainWork gate (Bitcoin Core validation.cpp:4229).
            #
            # When the caller has NOT already cleared this batch via the
            # PRESYNC / headerssync state machine (``min_pow_checked=False``),
            # compute the cumulative proof-of-work contributed by every header
            # in the current validated-headers queue and reject the batch if it
            # falls below ``nMinimumChainWork``.  This closes the dead-helper
            # gap: ``validate_minimum_chain_work`` exists in the Rust
            # ``PyChainParams`` / ``ferrous-utils/sync/src/validate/header.rs``
            # but was never wired from Python; the equivalent Python path uses
            # ``_sync_module.get_minimum_chain_work`` from config.py, which
            # also delegates to the same Rust symbol.
            #
            # The check is placed AFTER the per-header PoW + chain-continuity
            # loop so that we roll back only NEW headers (accepted in this
            # batch) when the threshold isn't met — consistent with Core
            # rejecting each header individually when min_pow_checked=False
            # (the batch semantics here are equivalent: all-or-nothing per
            # call, matching ``ProcessNewBlockHeaders``' early-exit semantics).
            if accepted > 0 and not min_pow_checked and _has_sync_module:
                try:
                    min_work_hex = _sync_module.get_minimum_chain_work(
                        self.peer_manager.network
                        if hasattr(self.peer_manager, "network")
                        else "mainnet"
                    )
                    min_work_int = int(min_work_hex, 16)
                    if min_work_int > 0:
                        # Compute the TOTAL chain work of the candidate chain,
                        # exactly as Bitcoin Core does in
                        # net_processing.cpp::TryLowWorkHeadersSync:
                        #     total_work = chain_start_header.nChainWork
                        #                  + CalculateClaimedHeadersWork(headers)
                        # i.e. the work of the block the new headers fork
                        # FROM, plus the work of the new headers themselves.
                        #
                        # `_validated_headers` only holds headers not yet
                        # downloaded as blocks; it always connects to our
                        # active DB tip (enforced by the `expected_prev`
                        # anchor + per-header chain-continuity check above).
                        # The base term is therefore the cumulative chain
                        # work already stored at the DB tip.  Omitting it —
                        # the pre-fix behaviour — measured only the work of
                        # the few thousand in-flight headers and rejected
                        # EVERY batch with `too-little-chainwork` once the
                        # node was past genesis, wedging sync indefinitely
                        # (mainnet stall at h=948464, 2026-05-19).
                        base_chain_work = 0
                        try:
                            _, _db_tip_height = self.db.get_best_block()
                            _base = self.db.get_chainwork_by_height(
                                _db_tip_height
                            )
                            # Coerce defensively: an older Rust build (or a
                            # test stub) may return a non-int.  Falling back
                            # to a 0 base only makes the gate STRICTER, never
                            # weaker, so it is always safe.
                            base_chain_work = int(_base) if _base else 0
                            # Snapshot-offset correction.  A datadir
                            # bootstrapped from an assumeUTXO snapshot
                            # BEFORE the snapshot loader persisted the
                            # snapshot block's BlockMetadata has every
                            # post-snapshot block's stored chainwork
                            # accumulated from 0 — ~32x too small — so
                            # this raw `base` understates the true
                            # cumulative work and the gate below rejects
                            # every honest mainnet batch (the
                            # too-little-chainwork brick, 2026-05-19).
                            # `detect_snapshot_chainwork_offset` returns
                            # the canonical snapshot-height chainwork to
                            # add back; it returns 0 for a correctly
                            # built datadir, so adding it is always safe
                            # and never weakens the gate.
                            try:
                                base_chain_work += (
                                    self._snapshot_chainwork_offset()
                                )
                            except Exception as _oe:
                                logger.debug(
                                    f"G8: snapshot-offset detect failed "
                                    f"({_oe}); using uncorrected base"
                                )
                        except Exception as _e:
                            logger.debug(
                                f"G8: could not read DB-tip chainwork "
                                f"({_e}); using 0 base"
                            )
                        headers_work = sum(
                            self._bits_to_work(int(hdr.bits))
                            for _, hdr in self._validated_headers
                        )
                        batch_work = base_chain_work + headers_work
                        if batch_work < min_work_int:
                            # Roll back: remove the headers we just appended.
                            del self._validated_headers[-accepted:]
                            self._headers_pow_rejected += accepted
                            logger.warning(
                                f"Batch of {accepted} headers from "
                                f"{peer.host}:{peer.port} rejected: "
                                f"cumulative work {batch_work:#066x} "
                                f"(base {base_chain_work:#066x} + headers "
                                f"{headers_work:#066x}) < nMinimumChainWork "
                                f"{min_work_int:#066x} "
                                f"(too-little-chainwork; G8)"
                            )
                            peer.adjust_score(-20)
                            if hasattr(self.peer_manager, "misbehaving"):
                                addr = f"{peer.host}:{peer.port}"
                                self.peer_manager.misbehaving(
                                    addr, 20, "too-little-chainwork"
                                )
                            self._drop_presync_state(peer)
                            return
                except Exception as _e:
                    # Defense-in-depth: a Rust-side error in
                    # get_minimum_chain_work must NOT break header sync.
                    # Log and continue — the presync state machine is the
                    # primary anti-DoS defense; this gate is defense-in-depth.
                    logger.debug(
                        f"get_minimum_chain_work raised: {_e} — "
                        f"skipping G8 check for this batch"
                    )

            # Successful connecting batch resets the per-peer
            # unconnecting-headers counter (Core's
            # ``nUnconnectingHeaders = 0`` in the success path).
            if accepted > 0:
                self._reset_unconnecting_headers(peer)

            # Hand the freshly-accepted, PoW-validated, chain-connected
            # headers to the Rust ``PyHeadersSyncState`` for commitment
            # tracking + cumulative-work accounting.  This is the
            # defense-in-depth presync layer: even if an attacker were to
            # somehow slip past the per-header PoW gate (e.g., via a fork
            # of unbounded difficulty drops), the cumulative-work check
            # vs ``nMinimumChainWork`` and the 1-bit commitments still
            # detect bogus chains.
            #
            # Note: we feed only freshly-appended headers, not duplicates
            # already in our queue.  Errors from the Rust state machine
            # are logged + the state is dropped (it self-finalises to
            # ``Final``); failure does NOT roll back the per-header
            # accept already done — the PoW gate above is the
            # consensus-relevant gate, the presync is anti-DoS only.
            # Track whether the presync state machine requested an
            # additional GETHEADERS even though this message was not full.
            # This happens on PRESYNC→REDOWNLOAD transition: the state
            # machine signals request_more=True regardless of message size
            # so that we re-request headers from the chain start for the
            # redownload pass.  Mirrors Core's ProcessNextHeaders logic:
            #   if (full_headers_message || state == REDOWNLOAD) request_more = true
            # headerssync.cpp:85-89.
            _presync_request_more: bool = False

            if presync_feed:
                presync = self._get_presync_state(peer)
                if presync is not None:
                    try:
                        full_message = len(headers_msg.headers) >= 2000
                        serialized = [h.serialize() for h in presync_feed]
                        result = presync.process_headers(serialized, full_message)
                        if not result.success:
                            self._headers_presync_failures += 1
                            logger.warning(
                                f"PyHeadersSyncState rejected batch from "
                                f"{peer.host}:{peer.port}: {result.error}"
                            )
                            self._drop_presync_state(peer)
                        else:
                            # Bug 6 fix: honour request_more from the state
                            # machine even when the message is not full.
                            # When PRESYNC transitions to REDOWNLOAD on a
                            # sub-2000-header batch the Rust side sets
                            # request_more=True; we must propagate that so
                            # the continuation GETHEADERS fires.
                            # Core: headerssync.cpp:85-89.
                            _presync_request_more = bool(result.request_more)
                    except Exception as e:
                        # Defense-in-depth only: a Rust-side error here
                        # must not break header sync.  Log + drop the
                        # state so a later batch can retry from scratch.
                        logger.debug(
                            f"PyHeadersSyncState.process_headers raised: {e}"
                        )
                        self._drop_presync_state(peer)

            if accepted:
                logger.info(
                    f"Validated {accepted} new headers (queue: {len(self._validated_headers)})"
                )
                # Reset sync peer stall timer on successful headers
                if peer == self._header_sync_peer:
                    self._header_sync_time = time.time()
                # Kick off block downloads for the next window.
                await self._request_next_blocks()

                # Ask for more headers when:
                #   (a) full batch (2000 headers) — more likely available, OR
                #   (b) presync state machine flagged request_more — signals
                #       a PRESYNC→REDOWNLOAD transition that requires a
                #       continuation even on a sub-2000 batch.
                # Core: ProcessNextHeaders request_more logic — headerssync.cpp:84-89.
                if len(headers_msg.headers) >= 2000 or _presync_request_more:
                    # Send continuation to the SAME peer (which is the sync
                    # peer).  This ensures sequential header batches from one
                    # peer, avoiding out-of-order interleaving.
                    target = self._header_sync_peer if self._header_sync_peer and self._header_sync_peer.is_connected() else peer
                    network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
                    last_hash = self._validated_headers[-1][0]
                    getheaders = GetHeadersMessage(
                        version=70015,
                        locator_hashes=[last_hash],
                        hash_stop=b'\x00' * 32,
                    )
                    try:
                        await target.send_message(getheaders.to_network_message(network))
                        self._header_sync_time = time.time()
                        logger.info(f"Requesting more headers after {last_hash.hex()[:16]}... from {target.host}")
                    except Exception as e:
                        logger.error(f"Failed to request continuation headers: {e}")

        except Exception as e:
            logger.error(f"Error handling headers from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)
            if hasattr(self.peer_manager, 'misbehaving'):
                addr = f"{peer.host}:{peer.port}"
                self.peer_manager.misbehaving(addr, 20, f"invalid headers: {e}")

    async def _request_next_blocks(self):
        """Request blocks from the validated header queue up to the in-flight limit.

        Anchored to the connected tip: only requests blocks that are within
        _max_blocks_in_flight of the last block we've actually stored in the
        DB.  This ensures blocks arrive roughly in order and can chain
        sequentially, avoiding orphan cascades.
        """
        if not self._validated_headers:
            return

        network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"

        # Slot 0 of `_validated_headers` is the next block to request after
        # our active tip (invariant enforced by the chain-prev check in
        # handle_headers and the anchor check in _drain_block_buffer_locked).
        # We MUST NOT use db.has_block_hash here to "skip already-connected
        # slots": that probe returns True for any block ever stored,
        # including blocks disconnected from the active chain by a rollback
        # or reorg, which advances `start` past orphaned hashes and ends up
        # requesting a block several heights above tip+1 — the 938231
        # misalignment wedge from 2026-05-02.
        _, current_height = self.db.get_best_block()
        start = 0
        in_flight = len(self.requested_blocks)
        cap_inflight = max(0, self._max_blocks_in_flight - in_flight)

        # W93: throttle new requests against IBD-buffer pressure.  W92's
        # 2.7× rate gain accelerated the W85 wedge from ~10h to ~2h21m
        # because download outpaced drain — buffer filled with non-tip+1
        # blocks until next-expected arrivals were dropped at the cap.
        # Hold (buffer_used + in_flight) under buffer_safety × capacity
        # so the buffer never reaches the deadlock threshold.  Already-
        # in-flight blocks (including tip+1) and timed-out re-requests
        # bypass this cap; only NEW requests get held back.
        buffer_safety = 0.75
        buffer_target = int(self._max_ibd_buffer * buffer_safety)
        buffer_used = len(self._ibd_block_buffer)
        cap_buffer = max(0, buffer_target - buffer_used - in_flight)
        throttled_by_buffer = cap_buffer < cap_inflight

        # W100: the head-of-window slots (first HEAD_OF_WINDOW headers not
        # yet on the active chain, starting at tip+1) MUST bypass cap_buffer
        # -- bounded only by cap_inflight and the per-peer cap, exactly as
        # this function's W93 comment above always CLAIMED but never
        # implemented. Without this, once in_flight drains to 0 while the
        # buffer sits at buffer_target (received blocks self-remove from
        # requested_blocks at handle_block but stay in the buffer),
        # cap_buffer == 0 and the one block that would let the drain advance
        # -- tip+1 -- is never re-requested by EITHER path (_handle_timeouts
        # only iterates requested_blocks, which is empty). Deadlock. This is
        # Core-faithful: Core (FindNextBlocks) always fetches the window-head
        # block, gated only by in-flight count, never by a receive buffer,
        # and SKIPS blocks it already has data for (net_processing.cpp
        # :1506-1511) -- which is why the HEAD pass below also skips slots
        # already sitting in _ibd_block_buffer.
        # Same head_set primitive as _handle_timeouts -- get_block_hash_by_height,
        # NOT has_block_hash, so orphaned blocks don't make us skip the
        # genuine head (the 938231 wedge guard).
        HEAD_OF_WINDOW = 8
        head_set: set[bytes] = set()
        for i, (bh, _) in enumerate(self._validated_headers):
            if self.db.get_block_hash_by_height(current_height + 1 + i) == bh:
                continue
            head_set.add(bh)
            if len(head_set) >= HEAD_OF_WINDOW:
                break

        to_request: list[tuple[int, bytes]] = []
        seen: set[bytes] = set()
        # HEAD pass: head-of-window slots bypass cap_buffer, capped only by
        # cap_inflight (and the per-peer cap, applied in distribution below).
        # Skip slots already in requested_blocks (in flight) or already in
        # _ibd_block_buffer (received out of order, awaiting drain) -- Core
        # FindNextBlocks does not re-fetch data it already holds. tip+1 in
        # the wedge is, by definition, NOT in the buffer (that is the
        # deadlock), so it survives this skip and is requested.
        head_budget = cap_inflight
        for i in range(start, len(self._validated_headers)):
            if head_budget <= 0:
                break
            block_hash, _ = self._validated_headers[i]
            if block_hash not in head_set:
                continue
            if (block_hash in self.requested_blocks
                    or block_hash in seen
                    or block_hash in self._ibd_block_buffer):
                continue
            to_request.append((MSG_WITNESS_BLOCK, block_hash))
            seen.add(block_hash)
            head_budget -= 1

        # TAIL pass: NEW far-ahead requests stay throttled by cap_buffer.
        # Budget is what's left of cap_inflight after the head pass, clamped
        # by cap_buffer (the W93 throttle) -- this is the W85 over-fetch
        # guard, unchanged for speculative tail fetches.
        tail_budget = min(cap_inflight - len(to_request), cap_buffer)
        if tail_budget > 0:
            for i in range(start, len(self._validated_headers)):
                if tail_budget <= 0:
                    break
                block_hash, _ = self._validated_headers[i]
                if block_hash in self.requested_blocks or block_hash in seen:
                    continue
                to_request.append((MSG_WITNESS_BLOCK, block_hash))
                seen.add(block_hash)
                tail_budget -= 1

        if not to_request:
            return

        # Distribute across connected peers round-robin, respecting the
        # per-peer in-flight cap.
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            candidates = [p for p in self.peer_manager.get_all_ready_peers()
                          if isinstance(p, Peer) and p.is_connected()]
        else:
            candidates = []
        if not candidates:
            return

        # Sort peers by score (descending) so round-robin hands the
        # chain-closest (head-of-window) blocks to the highest-quality
        # peers first.  get_all_ready_peers() returns insertion order,
        # which consistently awarded candidates[0] to a slow peer during
        # W91 soaks (98% no-progress drains).
        candidates.sort(key=lambda p: -getattr(p, 'score', 100))

        peer_load = Counter(self._block_request_peer.values())
        per_peer, assigned = _distribute_blocks_round_robin(
            to_request, candidates, peer_load, MAX_BLOCKS_IN_FLIGHT_PER_PEER,
        )

        if not assigned:
            return

        now = time.time()
        for _, bh in assigned:
            self.requested_blocks[bh] = now
            self._record_first_request_time(bh, now)

        for target_peer, items in per_peer.items():
            if not items:
                continue
            try:
                getdata = GetDataMessage(inventory=items)
                await target_peer.send_message(getdata.to_network_message(network))
                for _, bh in items:
                    self._block_request_peer[bh] = target_peer
            except Exception as e:
                logger.error(f"Failed to send getdata to {target_peer.host}:{target_peer.port}: {e}")
                target_peer.adjust_score(-2)
                # Un-mark blocks we failed to dispatch so another peer can try them.
                for _, bh in items:
                    self.requested_blocks.pop(bh, None)
                    self._block_request_peer.pop(bh, None)

        deferred = len(to_request) - len(assigned)
        extra = f", deferred {deferred} (all peers at cap)" if deferred else ""
        if throttled_by_buffer:
            extra += f" [W93 throttle: buf={buffer_used}+inflight={in_flight}, target={buffer_target}]"
        logger.info(
            f"Requested {len(assigned)} blocks (tip+{start}, "
            f"in-flight: {in_flight}+{len(assigned)}/{self._max_blocks_in_flight}"
            f"{extra})"
        )

    def _queue_anchored_to_tip(self) -> bool:
        """Sanity check: does ``_validated_headers[0]`` extend our current
        chain tip?

        The intended invariant of ``_validated_headers`` is that slot 0 is
        always tip+1.  The queue can become stale across a chainstate
        rollback (e.g. ``dumptxoutset`` rolled tip from 938348 → 938230 on
        2026-05-02) or a reorg: the queue was built relative to the OLD
        tip, so its slot 0 now extends a block that is no longer the
        active tip.  Detecting that here lets the caller drop the queue
        rather than spinning the drain on stale slot indexes.

        Note: we deliberately do NOT consult ``has_block_hash`` /
        ``get_block_hash_by_height`` here.  Those CFs are not pruned on
        block disconnect — after a rollback they still point at the OLD
        chain's hashes, so using them to "skip already-connected" headers
        re-introduces exactly the 938231 wedge we are trying to avoid.
        Active-chain membership is defined by walkability from the actual
        tip via ``prev_blockhash``, which is what we check here.
        """
        if not self._validated_headers:
            return True  # vacuously anchored
        try:
            current_hash, _ = self.db.get_best_block()
        except Exception:
            return True  # cannot determine; conservative: assume OK
        _bh, hdr = self._validated_headers[0]
        return getattr(hdr, "prev_blockhash", None) == current_hash

    def _prune_validated_headers(self):
        """Drop the queue if it no longer anchors to the active chain tip.

        With the post-2026-05-02 fix, the per-connect path in
        ``_drain_block_buffer_locked`` pops connected headers itself, so
        this function is reduced to a stale-queue safety net: if some
        external code (rollback, reorg, RPC ``invalidateblock``) has
        moved the active tip out from under us, slot 0 of
        ``_validated_headers`` no longer extends ``get_best_block()``.
        Drop the queue rather than pretending the stale slots are
        connected — a hash-based prune would silently bury the
        misalignment under `has_block_hash` returning True for orphaned
        blocks.
        """
        if not self._validated_headers:
            return
        if not self._queue_anchored_to_tip():
            try:
                current_hash, _ = self.db.get_best_block()
                tip_short = current_hash.hex()[:16]
            except Exception:
                tip_short = "?"
            logger.warning(
                "[slot-misalign] _prune_validated_headers dropping stale "
                "queue (%d entries) — slot 0 no longer extends tip %s",
                len(self._validated_headers),
                tip_short,
            )
            self._validated_headers.clear()

    def _check_wedge_watchdog(self) -> None:
        """Emit a diagnostic WARN if the block-accept path looks wedged.

        Wedge preconditions (all of):
        - No tip advance in the last `_wedge_warn_after` seconds.
        - Non-empty validated-header queue (we have headers to connect).
        - Non-empty IBD block buffer (blocks arriving but not connecting).

        Rate-limited to one WARN every `_wedge_warn_every` seconds.
        See wave47-2026-04-16/W75-OUROBOROS-STALL.md for the manifestation
        this is designed to surface.
        """
        now = time.time()
        if now - self._last_wedge_warn < self._wedge_warn_every:
            return
        stale = now - self._last_tip_advance
        if stale < self._wedge_warn_after:
            return
        if not self._validated_headers:
            return  # caught up — stalling here is just "no new blocks to fetch"
        if not self._ibd_block_buffer:
            return  # downloader-bound, not accept-path-bound
        try:
            _, best_height = self.db.get_best_block()
        except Exception:
            best_height = -1
        logger.warning(
            f"[W75-WATCHDOG] tip-stall suspected: "
            f"no_advance_for={stale:.0f}s tip={best_height} "
            f"buffer={len(self._ibd_block_buffer)}/{self._max_ibd_buffer} "
            f"pending_headers={len(self._validated_headers)} "
            f"requested={len(self.requested_blocks)} "
            f"| counters recv={self._blk_received} "
            f"dup={self._blk_duplicate} buf={self._blk_buffered} "
            f"full={self._blk_buffer_full} short={self._blk_too_short} "
            f"err={self._blk_error} conn={self._blk_connected} "
            f"val_rej={self._blk_validate_rejected} "
            f"con_fail={self._blk_connect_failed}"
        )
        self._last_wedge_warn = now

    async def _announce_block(
        self, block: Block, block_hash: bytes, exclude_peer: Peer | None = None,
    ) -> None:
        """Announce a validated block to peers based on their preferences."""
        if not hasattr(self.peer_manager, 'get_all_ready_peers'):
            return
        network = getattr(self.peer_manager, 'network', 'mainnet')

        for p in self.peer_manager.get_all_ready_peers():
            if p is exclude_peer:
                continue
            try:
                if p.wants_cmpctblock:
                    import os

                    from ouroboros.compact_blocks import CompactBlock
                    nonce = int.from_bytes(os.urandom(8), 'little')
                    cb = CompactBlock.from_block(block, nonce)
                    msg = CmpctBlockMessage(payload_bytes=cb.serialize())
                    await p.send_message(msg.to_network_message(network))
                elif p.wants_headers:
                    hdr = BlockHeader(
                        version=block.version,
                        prev_blockhash=block.prev_blockhash,
                        merkle_root=block.merkle_root,
                        timestamp=block.timestamp,
                        bits=block.bits,
                        nonce=block.nonce,
                    )
                    msg = HeadersMessage(headers=[hdr])
                    await p.send_message(msg.to_network_message(network))
                else:
                    inv = InvMessage(inventory=[(INV_TYPE_BLOCK, block_hash)])
                    await p.send_message(inv.to_network_message(network))
            except Exception as e:
                logger.debug(f"Failed to announce block to {p.host}:{p.port}: {e}")

    async def _process_orphans(self, applied_block_hash: bytes) -> None:
        """Process orphan blocks that may now have their parent in our chain.

        ``validator.validate_block`` and ``validator.apply_block`` are
        synchronous and CPU-heavy (per-input script verification + UTXO
        mutation in the legacy Python path).  Run them in a worker
        thread so the event loop is not blocked for the orphan-drain
        window, mirroring the off-load done on the IBD drain path.
        """
        to_process = [
            (h, b) for h, b in self.orphan_blocks.items()
            if b.prev_blockhash == applied_block_hash
        ]

        for block_hash, block in to_process:
            del self.orphan_blocks[block_hash]

            valid, error = await asyncio.to_thread(
                self.validator.validate_block, block,
            )
            if not valid:
                logger.warning(f"Orphan block {block_hash.hex()[:16]}... invalid: {error}")
                continue

            # Orphan extends the block we just applied; check if it matches current tip
            current_hash, _ = self.db.get_best_block()
            if block.prev_blockhash != current_hash:
                # Orphan's parent is not current tip; might need reorg
                reorg_success = await self._handle_reorg(block, block_hash)
                if not reorg_success:
                    logger.error("Failed to handle reorg for orphan")
                else:
                    await self._process_orphans(block_hash)
            else:
                await asyncio.to_thread(self.validator.apply_block, block)
                block_height = block.height if hasattr(block, 'height') and block.height else 0
                logger.info(f"✓ Connected orphan block {block_height}: {block_hash.hex()[:16]}...")

                await self._announce_block(block, block_hash)
                await self._process_orphans(block_hash)

    async def _catch_up(self, peer: Peer, our_height: int):
        try:
            # Build locator
            locator = self._build_locator(our_height)

            if not locator:
                logger.warning("Could not build locator for catch-up")
                return

            # Request headers
            getheaders = GetHeadersMessage(
                version=70015,
                locator_hashes=locator,
                hash_stop=b'\x00' * 32
            )

            network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
            getheaders_msg = getheaders.to_network_message(network)

            await peer.send_message(getheaders_msg)
            logger.info(f"Requested headers from {peer.host}:{peer.port} (locator: {len(locator)} hashes)")

        except Exception as e:
            logger.error(f"Error in catch_up: {e}")
            peer.adjust_score(-2)

    def _build_locator(self, height: int) -> list[bytes]:
        """Build block locator (exponential spacing).

        Mirrors Bitcoin Core's ``LocatorEntries`` (chain.cpp:26):
        the FIRST entry is always the chain tip, and the rest walk back
        exponentially.  The peer iterates the locator front-to-back and
        sends headers starting from the child of the FIRST hash it
        recognises on its best chain — so if our tip is missing, the peer
        falls back to a much older block and we get a stream of headers
        whose ``prev_blockhash`` does not match our actual tip.

        Uses the cheap Rust-side ``get_block_hash_by_height`` which returns the
        32-byte hash directly, instead of the full block (which would force a
        complete tx-by-tx deserialisation of a ~1MB block through PyO3 just to
        read ``block.hash``). The locator is rebuilt every ``sync_loop`` tick
        (1s during IBD) so the savings are substantial at high tip heights.

        IMPORTANT (post-snapshot wedge fix, 2026-05-02): after a
        ``loadtxoutset`` recovery, ``BLOCK_INDEX_CF`` is empty for all
        snapshot-loaded heights — only META_CF gets ``best_block_hash`` /
        ``best_height`` updated.  ``get_block_hash_by_height(944183)`` then
        returns ``None`` and the old code silently dropped the entry,
        producing a locator full of stale low-height hashes from before
        the snapshot.  Every peer matched one of those tiny hashes
        instead of our tip, so the resulting headers' ``prev`` was
        ``ebf2a133...`` (height ~999) rather than our tip
        ``17d8ce98...`` (height 944183), and every batch was rejected
        with "does not connect".  Fix: anchor the locator on
        ``get_best_block().hash`` from META_CF — this is the
        authoritative tip and is always present.
        """
        locator: list[bytes] = []

        # Tip-first anchor (Bitcoin Core chain.cpp:34).  This is the
        # authoritative tip from META_CF, NOT a BLOCK_INDEX_CF lookup, so
        # it survives snapshot loads and rollbacks where the per-height
        # index is stale or missing.
        try:
            best_hash, best_height = self.db.get_best_block()
        except Exception:
            best_hash, best_height = None, height
        if isinstance(best_hash, (bytes, bytearray)) and len(best_hash) == 32:
            locator.append(bytes(best_hash))

        # Use the authoritative tip height as the start of the walk so we
        # don't walk past it from a stale ``height`` argument.
        if isinstance(best_height, int) and best_height >= 0:
            height = max(int(best_height), int(height))

        step = 1
        current_height = height - 1  # tip already added above

        while current_height > 0:
            block_hash = self.db.get_block_hash_by_height(current_height)
            if isinstance(block_hash, bytes) and len(block_hash) == 32:
                if block_hash not in locator:
                    locator.append(block_hash)

            # Exponential spacing: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, ...
            if len(locator) >= 10:
                step *= 2

            current_height -= step

            # Limit to reasonable depth
            if current_height < 0:
                break

        # Always include genesis
        genesis_hash = self.db.get_block_hash_by_height(0)
        if isinstance(genesis_hash, bytes) and len(genesis_hash) == 32:
            if genesis_hash not in locator:
                locator.append(genesis_hash)

        return locator

    def _get_sync_peer(self, our_height: int) -> Peer | None:
        """Pick a random peer that's ahead of us for header requests."""
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = list(peers.values())
        candidates = [
            p for p in peers
            if isinstance(p, Peer) and hasattr(p, 'start_height')
            and p.start_height > our_height and p.is_connected()
        ]
        if not candidates:
            return None
        return random.choice(candidates)

    def _get_peer_with_highest_block(self) -> Peer | None:
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = [p for p in peers.values() if hasattr(p, 'is_connected') and p.is_connected()]
            elif not isinstance(peers, list):
                peers = []

        if not peers:
            return None

        # Filter to Peer instances with start_height
        valid_peers = [p for p in peers if isinstance(p, Peer) and hasattr(p, 'start_height')]
        if not valid_peers:
            return None

        return max(valid_peers, key=lambda p: p.start_height)

    def _w76_record_phases(
        self, deserialize_ns: int, validate_ns: int, connect_ns: int
    ) -> None:
        """W76-PHASE: roll a per-block phase-timing tuple into the
        cross-impl phase-table rollup.

        Splitting this out of `_drain_block_buffer_locked` keeps the
        telemetry independently testable (mirrors the W77 pattern).
        Tracks sum + max per phase; max surfaces tail latency
        independently of the average.  Emits one log line every
        `_w76_log_every` blocks, then zeroes all counters.
        """
        self._w76_blocks += 1
        self._w76_deserialize_sum_ns += deserialize_ns
        self._w76_validate_sum_ns += validate_ns
        self._w76_connect_sum_ns += connect_ns
        if deserialize_ns > self._w76_deserialize_max_ns:
            self._w76_deserialize_max_ns = deserialize_ns
        if validate_ns > self._w76_validate_max_ns:
            self._w76_validate_max_ns = validate_ns
        if connect_ns > self._w76_connect_max_ns:
            self._w76_connect_max_ns = connect_ns
        if self._w76_blocks >= self._w76_log_every:
            n = self._w76_blocks
            ds_ms = self._w76_deserialize_sum_ns / n / 1_000_000
            va_ms = self._w76_validate_sum_ns / n / 1_000_000
            co_ms = self._w76_connect_sum_ns / n / 1_000_000
            ds_max_ms = self._w76_deserialize_max_ns / 1_000_000
            va_max_ms = self._w76_validate_max_ns / 1_000_000
            co_max_ms = self._w76_connect_max_ns / 1_000_000
            total_ms = ds_ms + va_ms + co_ms
            rate = (3600_000 / total_ms) if total_ms > 0 else 0
            logger.info(
                "[W76-PHASE] blocks=%d "
                "deserialize_avg_ms=%.1f deserialize_max_ms=%.0f "
                "validate_avg_ms=%.1f validate_max_ms=%.0f "
                "connect_avg_ms=%.1f connect_max_ms=%.0f "
                "total_avg_ms=%.1f (~%.0f blk/hr)",
                n, ds_ms, ds_max_ms, va_ms, va_max_ms, co_ms, co_max_ms,
                total_ms, rate,
            )
            self._w76_blocks = 0
            self._w76_deserialize_sum_ns = 0
            self._w76_validate_sum_ns = 0
            self._w76_connect_sum_ns = 0
            self._w76_deserialize_max_ns = 0
            self._w76_validate_max_ns = 0
            self._w76_connect_max_ns = 0

    def _w90_record_validate(
        self,
        validate_ns: int,
        via_rust: bool,
        skip_scripts: bool,
        tx_count: int,
        height: int,
    ) -> None:
        """W90: per-block validation-path breakdown.

        W76-PHASE pins ~90% of per-block wall-clock on 'validate' but
        doesn't reveal which validator ran or how the cost scales with
        tx count.  W90 splits validate by path (Rust vs Python),
        records whether assumevalid's skip_scripts applied, and emits a
        per-100-block rollup.  Outlier blocks (>8s validate) also log
        inline with height + tx_count for post-hoc correlation.
        """
        self._w90_blocks += 1
        self._w90_validate_sum_ns += validate_ns
        self._w90_tx_count_sum += tx_count
        if via_rust:
            self._w90_rust_used += 1
        else:
            self._w90_python_used += 1
        if skip_scripts:
            self._w90_skip_scripts_true += 1
        if validate_ns > self._w90_validate_max_ns:
            self._w90_validate_max_ns = validate_ns
        if validate_ns > self._w90_slow_threshold_ns:
            self._w90_slow_blocks += 1
            logger.info(
                "[W90-SLOW] h=%d validate_ms=%.0f tx_count=%d "
                "via_rust=%s skip_scripts=%s",
                height,
                validate_ns / 1_000_000,
                tx_count,
                via_rust,
                skip_scripts,
            )
        if self._w90_blocks >= self._w90_log_every:
            n = self._w90_blocks
            va_avg_ms = self._w90_validate_sum_ns / n / 1_000_000
            va_max_ms = self._w90_validate_max_ns / 1_000_000
            avg_tx = self._w90_tx_count_sum / n
            us_per_tx = (
                (self._w90_validate_sum_ns / self._w90_tx_count_sum) / 1000
                if self._w90_tx_count_sum > 0
                else 0.0
            )
            logger.info(
                "[W90-VAL] blocks=%d rust=%d python=%d skip_scripts=%d "
                "slow=%d validate_avg_ms=%.1f validate_max_ms=%.0f "
                "avg_tx=%.0f us_per_tx=%.0f",
                n,
                self._w90_rust_used,
                self._w90_python_used,
                self._w90_skip_scripts_true,
                self._w90_slow_blocks,
                va_avg_ms,
                va_max_ms,
                avg_tx,
                us_per_tx,
            )
            self._w90_blocks = 0
            self._w90_rust_used = 0
            self._w90_python_used = 0
            self._w90_skip_scripts_true = 0
            self._w90_tx_count_sum = 0
            self._w90_validate_sum_ns = 0
            self._w90_validate_max_ns = 0
            self._w90_slow_blocks = 0

    def _w91_record_connect(
        self, deserialize_ns: int, validate_ns: int, connect_ns: int
    ) -> None:
        """W91: per-block wall-clock + intra-drain gap.

        'wallclock_ns' is the time between this connect and the
        previous one (on any drain invocation).  'work_ns' is the sum
        of deserialize + validate + connect timers, i.e. actual
        compute for this block.  The difference is 'gap_ns' — async
        overhead (to_thread round-trip, asyncio.sleep(0), W76/W77/W90
        bookkeeping, mempool/fee/zmq post-processing) PLUS any time
        the drain loop was idle between exit and re-entry.

        Paired with the drain-level idle tracking in
        `_drain_block_buffer_locked`, this lets us separate 'drain
        loop is slow per block' (high gap, low drain_idle) from 'drain
        loop waits for peers' (low gap, high drain_idle).
        """
        now = time.perf_counter_ns()
        work_ns = deserialize_ns + validate_ns + connect_ns
        if self._w91_last_connect_perf_ns:
            wall_ns = now - self._w91_last_connect_perf_ns
            if wall_ns > 0:
                self._w91_blocks += 1
                self._w91_wallclock_sum_ns += wall_ns
                self._w91_work_sum_ns += work_ns
                if wall_ns > self._w91_wallclock_max_ns:
                    self._w91_wallclock_max_ns = wall_ns
        self._w91_last_connect_perf_ns = now
        if self._w91_blocks >= self._w91_log_every:
            n = self._w91_blocks
            wall_avg_ms = self._w91_wallclock_sum_ns / n / 1_000_000
            wall_max_ms = self._w91_wallclock_max_ns / 1_000_000
            work_avg_ms = self._w91_work_sum_ns / n / 1_000_000
            gap_avg_ms = max(0.0, wall_avg_ms - work_avg_ms)
            drain_entries = self._w91_drain_entries
            drain_noprog = self._w91_drain_noprogress
            drains_per_blk = drain_entries / n if n else 0.0
            buf_avg_entry = (
                self._w91_buffer_on_entry_sum / drain_entries
                if drain_entries else 0.0
            )
            # drain_idle averaged over drain entries that HAD a prior
            # exit (skip the very first).  Use drain_entries as
            # denominator (close enough; the −1 off-by-one is
            # negligible at N=100+).
            idle_avg_ms = (
                self._w91_drain_idle_sum_ns / drain_entries / 1_000_000
                if drain_entries else 0.0
            )
            idle_max_ms = self._w91_drain_idle_max_ns / 1_000_000
            rate = 3600_000 / wall_avg_ms if wall_avg_ms > 0 else 0
            logger.info(
                "[W91-WALL] blocks=%d wallclock_avg_ms=%.0f "
                "wallclock_max_ms=%.0f work_avg_ms=%.0f gap_avg_ms=%.0f "
                "drains=%d noprog=%d drains_per_blk=%.2f "
                "buffer_avg_on_entry=%.0f drain_idle_avg_ms=%.0f "
                "drain_idle_max_ms=%.0f (~%.0f blk/hr)",
                n, wall_avg_ms, wall_max_ms, work_avg_ms, gap_avg_ms,
                drain_entries, drain_noprog, drains_per_blk,
                buf_avg_entry, idle_avg_ms, idle_max_ms, rate,
            )
            self._w91_blocks = 0
            self._w91_wallclock_sum_ns = 0
            self._w91_wallclock_max_ns = 0
            self._w91_work_sum_ns = 0
            self._w91_drain_entries = 0
            self._w91_drain_noprogress = 0
            self._w91_drain_idle_sum_ns = 0
            self._w91_drain_idle_max_ns = 0
            self._w91_buffer_on_entry_sum = 0

    def _w77_record_connect(self, block_hash: bytes, connect_time: float) -> None:
        """W77: roll a successful connect into the 100-block timeout rollup.

        Splitting this out of `_drain_block_buffer_locked` keeps the
        telemetry independently testable.  Uses the ORIGINAL request time
        (first getdata) so a block re-requested three times before
        arriving is billed for the full elapsed wall-clock, not just the
        last hop.  Missing entries (pre-instrumentation restart, or a
        compact-block fast path that skips the request map) are treated
        as 0 so a missing baseline is not counted as infinite latency.
        """
        first_req = self._w77_first_request_time.pop(block_hash, None)
        # The block connected to the active chain — its in-flight bookkeeping
        # is done.  Drop the attempt counter so it cannot accrete across the
        # process lifetime (it is bumped per timeout in _handle_timeouts).
        self._block_request_attempts.pop(block_hash, None)
        if first_req is not None:
            lat_s = connect_time - first_req
            if lat_s < 0:
                lat_s = 0.0
            self._w77_latency_sum_s += lat_s
            if lat_s > self._w77_latency_max_s:
                self._w77_latency_max_s = lat_s
        self._w77_blocks += 1
        if self._w77_blocks >= 100:
            n = self._w77_blocks
            avg_ms = (self._w77_latency_sum_s / n) * 1000.0
            max_ms = self._w77_latency_max_s * 1000.0
            cycles = self._w77_timeout_cycles
            t_per_cycle = (self._w77_timeouts_total / cycles) if cycles else 0.0
            rr_total = sum(self._w77_rerequest_peer_counts.values())
            top_peers = self._w77_rerequest_peer_counts.most_common(3)
            top_str = ",".join(f"{p}={c}" for p, c in top_peers) or "-"
            logger.info(
                "[W77-TIMEOUT] blocks=%d req_connect_avg_ms=%.1f "
                "req_connect_max_ms=%.0f timeout_cycles=%d timeouts=%d "
                "t_per_cycle=%.1f failed_peers=%d rerequests=%d top3=%s",
                n, avg_ms, max_ms, cycles, self._w77_timeouts_total,
                t_per_cycle, len(self._w77_failed_peers), rr_total, top_str,
            )
            self._w77_blocks = 0
            self._w77_timeouts_total = 0
            self._w77_timeout_cycles = 0
            self._w77_failed_peers.clear()
            self._w77_rerequest_peer_counts.clear()
            self._w77_latency_sum_s = 0.0
            self._w77_latency_max_s = 0.0

    @staticmethod
    def _w95_compute_general_timeout(avg_mb: float, n_in_flight: int) -> float:
        """W95: size-aware general-path block-download timeout.

        Extracted so the arithmetic is unit-testable without spinning the
        full timeout loop.  See `_handle_timeouts` for the tuning rationale
        and the parameter rollout history (W82 60s uniform → W95 scaled).
        """
        W95_BASE_TIMEOUT_S = 20.0
        W95_PER_MB_S = 30.0
        W95_PER_IN_FLIGHT_S = 3.0
        W95_MIN_TIMEOUT = 20.0
        W95_MAX_TIMEOUT = 240.0
        mb = max(0.1, avg_mb)
        t = (
            W95_BASE_TIMEOUT_S
            + W95_PER_MB_S * mb
            + W95_PER_IN_FLIGHT_S * max(0, n_in_flight - 1)
        )
        if t < W95_MIN_TIMEOUT:
            return W95_MIN_TIMEOUT
        if t > W95_MAX_TIMEOUT:
            return W95_MAX_TIMEOUT
        return t

    async def _handle_timeouts(self):
        """Re-request blocks that timed out, rotating to a different peer each time."""
        now = time.time()
        # W92: split into a tight head-of-window rescue and the general
        # timeout path.  The W91 probe showed 98% of drains found no
        # next-expected block with the buffer holding 150-290 future
        # blocks — the chain-closest slot was held hostage by a slow
        # peer while later blocks piled up.  Rescue the first 8 unfetched
        # slots at HEAD_TIMEOUT so the drain can advance; penalize peer
        # score only on the general path (optimistic reroutes aren't a
        # verdict on peer quality).
        # HEAD_TIMEOUT=2s matches Bitcoin Core's BLOCK_STALLING_TIMEOUT
        # (net_processing.cpp).  Tightened from 10s in W94b (fc63a2f).
        #
        # W95: replace the uniform 60s general TIMEOUT with a size-aware
        # budget.  History: W82 had to restore 60s after a 20s regression
        # (rate 1117 → 580 blk/hr at h=817k) — big blocks plus saturated
        # per-peer queues need more time; small blocks don't.  60s is a
        # one-size-fits-all value that is too lenient for the early chain
        # (<500k, blocks <100 KB) and still too aggressive for 2 MB blocks
        # when MAX_BLOCKS_IN_FLIGHT_PER_PEER=16.  Formula below scales
        # with the recent-payload EMA and the per-peer in-flight count;
        # clamped to [MIN,MAX] so an outlier block can't wedge the loop.
        HEAD_OF_WINDOW = 8
        HEAD_TIMEOUT = 2.0

        # Build the head-of-window set: the first HEAD_OF_WINDOW headers
        # that are NOT yet on the active chain.  Active-chain membership
        # via get_block_hash_by_height (NOT has_block_hash) so orphaned
        # blocks don't make us skip the genuine head-of-window — same
        # rationale as `_first_unconnected_header_idx`.
        _, current_height = self.db.get_best_block()
        head_set: set[bytes] = set()
        for i, (bh, _) in enumerate(self._validated_headers):
            if self.db.get_block_hash_by_height(current_height + 1 + i) == bh:
                continue
            head_set.add(bh)
            if len(head_set) >= HEAD_OF_WINDOW:
                break

        # W95: snapshot per-peer in-flight counts before any reassignment
        # so the timeout scaling uses the true current load, not the
        # adjusted post-reassignment one recomputed later in this method.
        peer_load_snapshot: Counter = Counter(self._block_request_peer.values())
        avg_mb = max(0.1, self._w95_block_mb_ema)

        head_timed_out: list[bytes] = []
        general_timed_out: list[bytes] = []
        for block_hash, request_time in self.requested_blocks.items():
            elapsed = now - request_time
            if block_hash in head_set:
                if elapsed > HEAD_TIMEOUT:
                    head_timed_out.append(block_hash)
                continue
            req_peer = self._block_request_peer.get(block_hash)
            n_in_flight = peer_load_snapshot.get(req_peer, 1) if req_peer is not None else 1
            timeout = self._w95_compute_general_timeout(avg_mb, n_in_flight)
            if elapsed > timeout:
                general_timed_out.append(block_hash)
        timed_out = head_timed_out + general_timed_out

        if not timed_out:
            return

        # Bound the retry queue: count a re-request attempt for every timed-out
        # block and PERMANENTLY ABANDON any GENERAL-timeout block that has
        # exceeded BLOCK_REQUEST_MAX_ATTEMPTS.  Head-of-window blocks (tip+1
        # region) are exempt — those are on the active chain and must keep
        # being retried or sync wedges; abandoning the head is never correct.
        # General timeouts are off-active-chain announces (stale / fork /
        # competing tips a peer threw at us via inv): a peer announced them,
        # no peer delivers them into our chain, and pre-fix they were
        # re-requested forever, leaking one entry each in requested_blocks /
        # _block_request_peer / _w77_first_request_time (the at-tip RSS leak).
        # Perm-reject the abandoned hash so a redelivery / re-announce does not
        # re-open the same in-flight slot.
        head_set_for_attempts = set(head_timed_out)
        abandoned: list[bytes] = []
        for block_hash in timed_out:
            n = self._block_request_attempts.get(block_hash, 0) + 1
            self._block_request_attempts[block_hash] = n
            if (
                block_hash not in head_set_for_attempts
                and n > BLOCK_REQUEST_MAX_ATTEMPTS
            ):
                abandoned.append(block_hash)
        if abandoned:
            ab_set = set(abandoned)
            timed_out = [h for h in timed_out if h not in ab_set]
            general_timed_out = [h for h in general_timed_out if h not in ab_set]
            for block_hash in abandoned:
                # _mark_perm_rejected calls _abandon_block_request, which drops
                # the hash from all four in-flight maps.
                self._mark_perm_rejected(block_hash)
            logger.warning(
                "Abandoned %d block request(s) after %d failed attempts "
                "(off-active-chain announces never delivered) — dropped from "
                "in-flight maps + perm-rejected",
                len(abandoned), BLOCK_REQUEST_MAX_ATTEMPTS,
            )

        if not timed_out:
            return

        # Get all connected peers once for the whole batch
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            all_peers = [p for p in self.peer_manager.get_all_ready_peers()
                         if isinstance(p, Peer)]
        else:
            raw = getattr(self.peer_manager, 'peers', [])
            if isinstance(raw, dict):
                raw = list(raw.values())
            all_peers = [p for p in raw if isinstance(p, Peer)]

        # Penalize each failed peer only ONCE per cycle (not per block).
        # Only peers holding general (60s) timeouts get a score penalty;
        # head-of-window rescues at HEAD_TIMEOUT (2s) are optimistic
        # reroutes, not verdicts on peer quality — a legitimately-serving
        # peer might need >2s to deliver a 2 MB block.
        general_set = set(general_timed_out)
        failed_peers: set[Peer] = set()
        penalize_peers: set[Peer] = set()
        for block_hash in timed_out:
            failed_peer = self._block_request_peer.get(block_hash)
            if failed_peer is not None:
                failed_peers.add(failed_peer)
                if block_hash in general_set:
                    penalize_peers.add(failed_peer)
        for peer in penalize_peers:
            peer.adjust_score(-1)

        connected_peers = [p for p in all_peers if p.is_connected()]

        # If no peers available, clear all in-flight requests so they re-queue on reconnect
        if not connected_peers:
            logger.warning(
                f"{len(timed_out)} block requests timed out with 0 available peers, "
                f"clearing in-flight requests for re-queue"
            )
            for block_hash in timed_out:
                del self.requested_blocks[block_hash]
                self._block_request_peer.pop(block_hash, None)
                # Re-queue resets the retry budget; drop the attempt counter so
                # it cannot orphan-accrete across repeated no-peer windows.
                # _w77_first_request_time is left as the latency baseline (it is
                # FIFO-capped by _record_first_request_time as a backstop).
                self._block_request_attempts.pop(block_hash, None)
            return

        logger.warning(
            f"{len(timed_out)} block requests timed out "
            f"(head={len(head_timed_out)}/{len(head_set)}@{HEAD_TIMEOUT:.0f}s, "
            f"general={len(general_timed_out)} [W95 avg_mb={avg_mb:.2f}], "
            f"failed peers: {len(failed_peers)}, "
            f"penalized: {len(penalize_peers)}, "
            f"available peers: {len(connected_peers)})"
        )

        # W77: roll up timeout cycle into the 100-block window.
        self._w77_timeouts_total += len(timed_out)
        self._w77_timeout_cycles += 1
        for fp in failed_peers:
            self._w77_failed_peers.add(f"{fp.host}:{fp.port}")

        # Batch re-requests: round-robin across available peers, preferring non-failed ones
        preferred = [p for p in connected_peers if p not in failed_peers]
        if not preferred:
            preferred = connected_peers
        # W92: sort preferred by score (descending) so rescued head-of-
        # window blocks go to the highest-quality peers first.
        preferred.sort(key=lambda p: -getattr(p, 'score', 100))

        # Group re-requests by target peer, respecting the per-peer in-flight
        # cap.  `peer_load` starts from the live in-flight map minus the blocks
        # we're about to re-assign (they're still in _block_request_peer but
        # their old peer slot no longer counts toward capacity).
        peer_load = Counter(self._block_request_peer.values())
        for bh in timed_out:
            old_peer = self._block_request_peer.get(bh)
            if old_peer is not None and peer_load[old_peer] > 0:
                peer_load[old_peer] -= 1

        to_items = [(MSG_WITNESS_BLOCK, bh) for bh in timed_out]
        per_peer, assigned = _distribute_blocks_round_robin(
            to_items, preferred, peer_load, MAX_BLOCKS_IN_FLIGHT_PER_PEER,
        )
        assigned_hashes = {bh for _, bh in assigned}
        peer_batches: dict = {peer: [bh for _, bh in items] for peer, items in per_peer.items()}

        deferred_count = len(timed_out) - len(assigned_hashes)
        if deferred_count:
            # Leave deferred blocks' timestamps alone so the next cycle re-tries
            # them as soon as a peer frees a slot; don't drop them from the
            # in-flight map (they're still "ours" to reassign).
            logger.debug(
                f"Deferring re-request of {deferred_count} blocks: all peers "
                f"at per-peer cap ({MAX_BLOCKS_IN_FLIGHT_PER_PEER})"
            )

        network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"

        for peer, block_hashes in peer_batches.items():
            if not block_hashes:
                continue
            try:
                inventory = [(MSG_WITNESS_BLOCK, bh) for bh in block_hashes]
                getdata = GetDataMessage(inventory=inventory)
                getdata_msg = getdata.to_network_message(network)
                await peer.send_message(getdata_msg)
                for bh in block_hashes:
                    self.requested_blocks[bh] = now
                    self._block_request_peer[bh] = peer
                # W77: track re-request distribution across peers.
                self._w77_rerequest_peer_counts[f"{peer.host}:{peer.port}"] += len(block_hashes)
                logger.info(f"Re-requested {len(block_hashes)} blocks from {peer.host}:{peer.port}")
            except Exception as e:
                logger.error(f"Failed to re-request {len(block_hashes)} blocks from {peer.host}:{peer.port}: {e}")
                for bh in block_hashes:
                    self.requested_blocks.pop(bh, None)
                    self._block_request_peer.pop(bh, None)

    async def _handle_reorg(self, new_block: Block, new_chain_tip: bytes):
        """Handle chain reorganization.

        Disconnect side delegates to the Rust crate's
        ``disconnect_block_at_height`` (exposed as ``db.disconnect_block``):
        it loads the per-block undo record from SPENT_CF / UNDO_CF and
        restores each spent UTXO with its full ``Coin`` metadata
        (``height`` and ``is_coinbase`` are preserved — both were dropped
        on the floor by the previous Python implementation, breaking the
        coinbase-maturity rule for any tx that spent a coinbase across a
        reorg).  Reference: Bitcoin Core ``DisconnectBlock`` /
        ``ApplyTxInUndo`` (validation.cpp:2149+, 2179+).

        Connect side feeds the raw side-chain block bytes (witnesses
        included) back through ``connect_block_from_bytes`` so that the
        reorg leaves the chainstate, tx-index, and SPENT_CF undo records
        in the same shape as a fresh forward sync would have produced —
        important for any subsequent re-reorg that needs to disconnect
        the freshly connected blocks.

        Mempool refill: each non-coinbase tx from the disconnected
        side-chain is re-evaluated against the new tip via
        ``mempool.add_transaction`` (which runs BIP-113 / BIP-68
        / standardness against the current chain state).  Children of
        rejected txs are dropped implicitly because their parents are
        not in the UTXO set any more.
        """
        logger.warning(f"Handling chain reorganization to new tip: {new_chain_tip.hex()[:16]}...")

        # Clear signature cache on reorg to prevent stale entries from invalidated chain
        SIG_CACHE.clear()

        try:
            # Get current best block
            current_hash, current_height = self.db.get_best_block()

            if current_hash == new_chain_tip:
                # No reorg needed - we're already on this chain
                return True

            # Walk back chains to find common ancestor
            current_chain: list[tuple[bytes, Block, int]] = []
            new_chain: list[tuple[bytes, Block, int]] = []

            # Build current chain back to reasonable depth (e.g., 100 blocks)
            # Also track heights for transaction search.  Each get_block
            # call deserializes a full ~1 MB block over PyO3; the chain
            # walk can do up to 100 of them.  Off-load to a worker thread
            # so the asyncio loop stays responsive during the walk.
            temp_hash = current_hash
            temp_height = current_height
            for _ in range(100):
                if temp_hash is None:
                    break
                block = await asyncio.to_thread(self.db.get_block, temp_hash)
                if not block:
                    break
                # Store with height for easier lookup
                current_chain.append((temp_hash, block, temp_height))
                temp_hash = block.prev_blockhash
                temp_height -= 1
                if temp_hash == bytes(32):  # Genesis block
                    break

            # Build new chain back (new_block is the tip we received, may not be in db yet)
            temp_hash = new_chain_tip
            temp_height = current_height
            for _ in range(100):
                if temp_hash is None:
                    break
                # Use the block we received if it's the tip; otherwise get from db
                if temp_hash == new_chain_tip and new_block.hash == new_chain_tip:
                    block = new_block
                else:
                    block = await asyncio.to_thread(self.db.get_block, temp_hash)
                if not block:
                    logger.warning(
                        f"Block {temp_hash.hex()[:16]}... not in database, cannot complete reorg"
                    )
                    return False
                new_chain.append((temp_hash, block, temp_height))
                # Check if we found common ancestor
                if temp_hash in [h for h, _, _ in current_chain]:
                    # Found common ancestor - update height estimate
                    for curr_h, _, curr_ht in current_chain:
                        if curr_h == temp_hash:
                            temp_height = curr_ht
                            break
                    break
                temp_hash = block.prev_blockhash
                temp_height -= 1
                if temp_hash == bytes(32):  # Genesis block
                    break

            # Find common ancestor
            common_ancestor = None
            common_ancestor_height = 0
            for curr_hash, _, curr_height in current_chain:
                for new_hash, _, _new_height in new_chain:
                    if curr_hash == new_hash:
                        common_ancestor = curr_hash
                        # Use the height from current_chain
                        common_ancestor_height = curr_height
                        break
                if common_ancestor:
                    break

            if not common_ancestor:
                # No common ancestor found - this is a major reorg
                # May need to re-validate entire chain
                logger.warning("Major reorg detected - no common ancestor found within 100 blocks")
                return False

            blocks_to_disconnect = [
                (h, b, ht) for h, b, ht in current_chain
                if h != common_ancestor
            ]
            blocks_to_connect = list(reversed([
                (h, b, ht) for h, b, ht in new_chain
                if h != common_ancestor
            ]))

            logger.info(
                f"Reorg: common ancestor at height {common_ancestor_height}, "
                f"disconnecting {len(blocks_to_disconnect)} blocks, "
                f"connecting {len(blocks_to_connect)} blocks"
            )

            # ----------------------------------------------------------
            # Disconnect side: tip → fork point.
            #
            # ATOMICITY (CORE-PARITY-AUDIT/_chainstate-atomicity-family-
            # 2026-05-26.md): the chainstate disconnect now runs as a
            # SINGLE Rust ``WriteBatch`` via ``db.disconnect_blocks_atomic``
            # (matches the submitblock-driven reorg in ``rpc.py``).  Per-
            # block ``db.disconnect_block`` is NOT atomic — it issues N×
            # delete + M× put + 2× best-block-pointer puts as separate
            # RocksDB writes, with no HEAD_BLOCKS recovery marker.  A
            # process kill mid-disconnect (multi-block reorg or even a
            # single block with many txs) left CHAINSTATE_CF / SPENT_CF /
            # TX_INDEX_CF / META_CF in an inconsistent intermediate state
            # with no marker for ``recover_from_crash`` to detect.
            # Reference: storage/db.rs::disconnect_block_at_height_checked
            # (~300 LOC of separate writes) vs disconnect_blocks_atomic
            # (single batch).
            #
            # FIX-74 / W121 BUG-1: filter-index removal runs AFTER the
            # atomic chainstate disconnect lands.  Filter-index updates
            # were always best-effort (errors logged, never aborting the
            # reorg); preserving them in a separate post-disconnect loop
            # keeps the same hook semantics while making the chainstate
            # half atomic.  Mirrors Bitcoin Core's BlockFilterIndex::
            # CustomRewind via the CValidationInterface BlockDisconnected
            # callback (src/index/blockfilterindex.cpp + src/index/base.cpp).
            # ----------------------------------------------------------
            tip_height_at_disconnect = (
                common_ancestor_height + len(blocks_to_disconnect)
            )
            if hasattr(self.db, "disconnect_blocks_atomic") and blocks_to_disconnect:
                try:
                    await asyncio.to_thread(
                        self.db.disconnect_blocks_atomic,
                        tip_height_at_disconnect,
                        common_ancestor_height,
                    )
                except Exception as e:
                    logger.error(
                        f"Reorg disconnect_blocks_atomic("
                        f"{tip_height_at_disconnect}→{common_ancestor_height}) "
                        f"failed: {e}"
                    )
                    return False
            else:
                # Compatibility fallback: older Rust extensions without the
                # atomic helper retain the pre-Pattern-D per-block path
                # (per-block-non-atomic, multi-block sequential).
                disconnect_height = tip_height_at_disconnect
                for curr_hash, _curr_block, _ in reversed(blocks_to_disconnect):
                    logger.debug(
                        f"Disconnecting block {curr_hash.hex()[:16]}... at height {disconnect_height}"
                    )
                    try:
                        await asyncio.to_thread(
                            self.db.disconnect_block, disconnect_height
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to disconnect block at height {disconnect_height} "
                            f"(hash {curr_hash.hex()[:16]}...): {e}"
                        )
                        return False
                    disconnect_height -= 1

            # FIX-74 / W121 BUG-1: remove each disconnected block from the
            # BIP-157/158 filter index.  Non-fatal: an index fault must
            # never abort the reorg (matches the linear-connect hook's
            # "log and continue" policy at line ~1370).  Activates
            # FIX-71's best_indexed_height rollback machinery (wired into
            # PersistentBlockFilterIndex.remove() but never called pre-
            # FIX-74 because the reorg loop didn't hook it).
            if self.block_filter_index is not None:
                disconnect_height = tip_height_at_disconnect
                for curr_hash, _curr_block, _ in reversed(blocks_to_disconnect):
                    try:
                        await asyncio.to_thread(
                            self.block_filter_index.remove,
                            curr_hash,
                            disconnect_height,
                        )
                    except TypeError:
                        # In-memory BlockFilterIndex.remove() does not take
                        # a height kwarg; it rolls back best_indexed_height
                        # internally via the _height_to_hash mapping.
                        try:
                            await asyncio.to_thread(
                                self.block_filter_index.remove, curr_hash
                            )
                        except Exception as e:
                            logger.warning(
                                f"block_filter_index.remove failed at "
                                f"height {disconnect_height} "
                                f"(hash {curr_hash.hex()[:16]}...): {e}"
                            )
                    except Exception as e:
                        logger.warning(
                            f"block_filter_index.remove failed at "
                            f"height {disconnect_height} "
                            f"(hash {curr_hash.hex()[:16]}...): {e}"
                        )
                    disconnect_height -= 1

            # Sanity: tip should now be at the common ancestor height.
            tip_hash, tip_height = self.db.get_best_block()
            if tip_hash != common_ancestor:
                logger.error(
                    f"Reorg disconnect left tip at {tip_hash.hex()[:16]}... "
                    f"(height {tip_height}); expected common ancestor "
                    f"{common_ancestor.hex()[:16]}... at {common_ancestor_height}"
                )
                return False

            # FIX-74 / W121 BUG-1: rebase the filter header chain on the
            # common ancestor's filter header so subsequent ``add_block``
            # calls compute ``H_new = dSHA256(filter_hash_new || H_ancestor)``
            # — matching the active chain.  When the index has no header for
            # the common ancestor (e.g. it pre-dates the index, or genesis),
            # fall back to all-zeros, which is the canonical Core "genesis
            # prev" sentinel.  Non-fatal on lookup error: a stale tip_header
            # at worst forks the filter chain (BUG-1 worst case) but never
            # breaks consensus.
            if self.block_filter_index is not None:
                try:
                    ancestor_header = self.block_filter_index.get_header(
                        common_ancestor
                    )
                    if ancestor_header is None:
                        ancestor_header = b"\x00" * 32
                    await asyncio.to_thread(
                        self.block_filter_index.set_tip_header, ancestor_header
                    )
                except Exception as e:
                    logger.warning(
                        f"block_filter_index.set_tip_header rollback "
                        f"failed at common ancestor "
                        f"{common_ancestor.hex()[:16]}...: {e}"
                    )

            # ----------------------------------------------------------
            # Connect side: fork point + 1 → new tip.  Feed the raw
            # block bytes (witnesses included) into the Rust connect
            # path so that SPENT_CF undo records are written for the new
            # chain — required for a clean disconnect if we re-reorg
            # later.
            #
            # FIX-74 / W121 BUG-2: after each successful connect we also
            # call ``block_filter_index.add_block(block, height)`` so the
            # index re-builds filters along the new active chain.  This
            # mirrors the linear connect hook at line ~1362 and Core's
            # BlockFilterIndex::CustomAppend via the BlockConnected
            # callback (src/index/blockfilterindex.cpp +
            # src/index/base.cpp).
            # ----------------------------------------------------------
            for new_hash, new_block_obj, _new_height in blocks_to_connect:
                connect_height = self.db.get_best_block()[1] + 1
                logger.debug(
                    f"Connecting block {new_hash.hex()[:16]}... at height {connect_height}"
                )

                raw_bytes: bytes | None = None
                if hasattr(self.db, "get_block_bytes"):
                    try:
                        raw_bytes = self.db.get_block_bytes(new_hash)
                    except Exception as e:
                        logger.warning(
                            f"get_block_bytes failed for {new_hash.hex()[:16]}...: {e}"
                        )
                        raw_bytes = None

                if raw_bytes is None and getattr(new_block_obj, "raw_payload", None):
                    raw_bytes = new_block_obj.raw_payload

                if raw_bytes is None:
                    # Last-ditch fallback: re-serialize from the Python
                    # Block object.  This drops witness data, so consensus
                    # checks on segwit blocks may misbehave under this
                    # branch.  Keep the path so a missing-bytes case fails
                    # loudly rather than silently committing wrong state.
                    logger.error(
                        f"Reorg connect: no raw bytes available for "
                        f"{new_hash.hex()[:16]}... at height {connect_height}; "
                        f"refusing to fall back to witness-stripped serialize()"
                    )
                    return False

                try:
                    if hasattr(self.db, "connect_block_from_bytes"):
                        await asyncio.to_thread(
                            self.db.connect_block_from_bytes, raw_bytes, connect_height
                        )
                    else:
                        # Last-resort path used only when the Rust
                        # extension is not built (e.g. pure-Python tests).
                        valid, error = self.validator.validate_block(new_block_obj)
                        if not valid:
                            logger.error(
                                f"Invalid block in reorg: {new_hash.hex()[:16]}... - {error}"
                            )
                            return False
                        self.validator.apply_block(new_block_obj)
                        self.db.update_best_block(new_hash, connect_height)
                except Exception as e:
                    logger.error(
                        f"Error connecting block {new_hash.hex()[:16]}... "
                        f"at height {connect_height} during reorg: {e}"
                    )
                    return False

                # FIX-74 / W121 BUG-2: re-index the newly connected block
                # in the BIP-157/158 filter index.  Mirrors the off-thread
                # hook from the linear connect path at line ~1362.  Errors
                # are non-fatal so an index fault never aborts the reorg.
                if self.block_filter_index is not None:
                    try:
                        await asyncio.to_thread(
                            self.block_filter_index.add_block,
                            new_block_obj,
                            connect_height,
                            self.db,
                        )
                    except Exception as e:
                        logger.warning(
                            f"block_filter_index.add_block failed at "
                            f"height {connect_height} during reorg "
                            f"(hash {new_hash.hex()[:16]}...): {e}"
                        )

                # Remove transactions now in block from mempool.
                if self.mempool:
                    self.mempool.remove_block_transactions(new_block_obj)

                # Process orphans that may now have their parent
                await self._process_orphans(new_hash)

            final_hash, final_height = self.db.get_best_block()

            # ----------------------------------------------------------
            # Mempool refill: re-add disconnected-block txs to the
            # mempool subject to the new tip's policy. ``add_transaction``
            # runs the same checks as a freshly received tx (BIP-113
            # IsFinalTx, BIP-68 SequenceLocks, standardness, double-spend
            # against new-chain UTXOs), so this is policy-correct against
            # the new tip.
            #
            # Off-load each ATMP via asyncio.to_thread: with up to ~200
            # tx per block × tens of blocks on a deep reorg, doing the
            # refill on the event loop would freeze RPC + P2P dispatch
            # for the entire refill window.  Mirrors the off-load done
            # in node._make_tx_handler / rpc_sendrawtransaction.
            # ----------------------------------------------------------
            if self.mempool:
                for _, curr_block, _ in reversed(blocks_to_disconnect):
                    for tx in curr_block.transactions:
                        if tx.is_coinbase:
                            continue
                        try:
                            success, reason = await asyncio.to_thread(
                                self.mempool.add_transaction, tx, final_height,
                            )
                            if success:
                                logger.debug(
                                    f"Re-added tx {tx.get_txid().hex()[:16]}... to mempool"
                                )
                            else:
                                logger.debug(
                                    f"Tx {tx.get_txid().hex()[:16]}... not re-added to mempool: {reason}"
                                )
                        except Exception as e:
                            logger.debug(
                                f"Error re-adding tx {tx.get_txid().hex()[:16]}...: {e}"
                            )

            logger.info(f"Reorg handled: new tip at height {final_height}")
            self.reorg_depth += 1
            return True

        except Exception as e:
            logger.error(f"Error handling reorg: {e}", exc_info=True)
            return False
