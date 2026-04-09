"""
Prometheus metrics for Ouroboros node monitoring.

Metrics are only registered when ``init_metrics()`` is called.  If
``prometheus_client`` is not installed the module degrades gracefully:
all public helpers become no-ops and ``init_metrics`` returns False.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        start_http_server,
    )

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False

# Sentinel values replaced by real metrics in ``init_metrics()``.
BLOCK_HEIGHT: Optional["Gauge"] = None
CHAIN_DIFFICULTY: Optional["Gauge"] = None
PEERS_CONNECTED: Optional["Gauge"] = None

MEMPOOL_SIZE: Optional["Gauge"] = None
MEMPOOL_TX_COUNT: Optional["Gauge"] = None

# Standard bitcoin_* metrics
BITCOIN_BLOCKS_TOTAL: Optional["Gauge"] = None
BITCOIN_PEERS_CONNECTED: Optional["Gauge"] = None
BITCOIN_MEMPOOL_SIZE: Optional["Gauge"] = None

# UTXO cache metrics
UTXO_CACHE_SIZE: Optional["Gauge"] = None
UTXO_CACHE_MEMORY: Optional["Gauge"] = None
UTXO_CACHE_DIRTY: Optional["Gauge"] = None
UTXO_CACHE_HIT_RATE: Optional["Gauge"] = None
UTXO_CACHE_FLUSHES: Optional["Counter"] = None

BLOCKS_RECEIVED: Optional["Counter"] = None
TX_RECEIVED: Optional["Counter"] = None
PEER_DISCONNECTS: Optional["Counter"] = None

# Stale tip detection metrics
STALE_TIP_DETECTED: Optional["Counter"] = None
PEER_EVICTIONS: Optional["Counter"] = None

RPC_REQUESTS: Optional["Counter"] = None
RPC_DURATION: Optional["Histogram"] = None

NODE_INFO: Optional["Info"] = None

_initialised = False


def init_metrics(port: int = 9332) -> bool:
    """
    Create Prometheus metrics and start the HTTP exporter.

    Returns True if metrics are available, False if ``prometheus_client``
    is missing.
    """
    global BLOCK_HEIGHT, CHAIN_DIFFICULTY, PEERS_CONNECTED
    global MEMPOOL_SIZE, MEMPOOL_TX_COUNT
    global BITCOIN_BLOCKS_TOTAL, BITCOIN_PEERS_CONNECTED, BITCOIN_MEMPOOL_SIZE
    global UTXO_CACHE_SIZE, UTXO_CACHE_MEMORY, UTXO_CACHE_DIRTY
    global UTXO_CACHE_HIT_RATE, UTXO_CACHE_FLUSHES
    global BLOCKS_RECEIVED, TX_RECEIVED, PEER_DISCONNECTS
    global STALE_TIP_DETECTED, PEER_EVICTIONS
    global RPC_REQUESTS, RPC_DURATION, NODE_INFO
    global _initialised

    if _initialised:
        return True

    if not _HAS_PROMETHEUS:
        logger.info("prometheus_client not installed — metrics disabled")
        return False

    BLOCK_HEIGHT = Gauge("ouroboros_block_height", "Current block height")
    CHAIN_DIFFICULTY = Gauge("ouroboros_chain_difficulty", "Current chain difficulty")
    PEERS_CONNECTED = Gauge("ouroboros_peers_connected", "Number of connected peers")

    MEMPOOL_SIZE = Gauge("ouroboros_mempool_size", "Mempool size in bytes")
    MEMPOOL_TX_COUNT = Gauge("ouroboros_mempool_tx_count", "Mempool transaction count")

    # Standard bitcoin_* metrics for cross-node monitoring
    BITCOIN_BLOCKS_TOTAL = Gauge("bitcoin_blocks_total", "Current block height")
    BITCOIN_PEERS_CONNECTED = Gauge("bitcoin_peers_connected", "Number of connected peers")
    BITCOIN_MEMPOOL_SIZE = Gauge("bitcoin_mempool_size", "Mempool transaction count")

    # UTXO cache metrics
    UTXO_CACHE_SIZE = Gauge("ouroboros_utxo_cache_size", "UTXO cache entry count")
    UTXO_CACHE_MEMORY = Gauge(
        "ouroboros_utxo_cache_memory_bytes", "UTXO cache memory usage in bytes"
    )
    UTXO_CACHE_DIRTY = Gauge(
        "ouroboros_utxo_cache_dirty", "Number of dirty entries in UTXO cache"
    )
    UTXO_CACHE_HIT_RATE = Gauge(
        "ouroboros_utxo_cache_hit_rate", "UTXO cache hit rate (0.0-1.0)"
    )
    UTXO_CACHE_FLUSHES = Counter(
        "ouroboros_utxo_cache_flushes_total", "Total number of UTXO cache flushes"
    )

    BLOCKS_RECEIVED = Counter("ouroboros_blocks_received_total", "Blocks received")
    TX_RECEIVED = Counter("ouroboros_tx_received_total", "Transactions received")
    PEER_DISCONNECTS = Counter("ouroboros_peer_disconnects_total", "Peer disconnections")

    STALE_TIP_DETECTED = Counter(
        "ouroboros_stale_tip_detected_total", "Stale tip detection events"
    )
    PEER_EVICTIONS = Counter(
        "ouroboros_peer_evictions_total", "Peer eviction events", ["reason"]
    )

    RPC_REQUESTS = Counter(
        "ouroboros_rpc_requests_total", "RPC requests", ["method"]
    )
    RPC_DURATION = Histogram(
        "ouroboros_rpc_duration_seconds", "RPC request duration", ["method"]
    )

    NODE_INFO = Info("ouroboros_node", "Node information")

    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics server listening on :{port}")
    except OSError as exc:
        logger.warning(f"Could not start metrics server on :{port}: {exc}")

    _initialised = True
    return True


# convenience helpers (safe to call even when metrics are disabled)


def update_chain_metrics(height: int, difficulty: float, peers: int) -> None:
    if BLOCK_HEIGHT is not None:
        BLOCK_HEIGHT.set(height)
    if CHAIN_DIFFICULTY is not None:
        CHAIN_DIFFICULTY.set(difficulty)
    if PEERS_CONNECTED is not None:
        PEERS_CONNECTED.set(peers)
    if BITCOIN_BLOCKS_TOTAL is not None:
        BITCOIN_BLOCKS_TOTAL.set(height)
    if BITCOIN_PEERS_CONNECTED is not None:
        BITCOIN_PEERS_CONNECTED.set(peers)


def update_mempool_metrics(size_bytes: int, tx_count: int) -> None:
    if MEMPOOL_SIZE is not None:
        MEMPOOL_SIZE.set(size_bytes)
    if MEMPOOL_TX_COUNT is not None:
        MEMPOOL_TX_COUNT.set(tx_count)
    if BITCOIN_MEMPOOL_SIZE is not None:
        BITCOIN_MEMPOOL_SIZE.set(tx_count)


def record_rpc_request(method: str, duration: float) -> None:
    if RPC_REQUESTS is not None:
        RPC_REQUESTS.labels(method=method).inc()
    if RPC_DURATION is not None:
        RPC_DURATION.labels(method=method).observe(duration)


def record_block_received() -> None:
    if BLOCKS_RECEIVED is not None:
        BLOCKS_RECEIVED.inc()


def record_tx_received() -> None:
    if TX_RECEIVED is not None:
        TX_RECEIVED.inc()


def record_peer_disconnect() -> None:
    if PEER_DISCONNECTS is not None:
        PEER_DISCONNECTS.inc()


def record_stale_tip_detected() -> None:
    """Record a stale tip detection event."""
    if STALE_TIP_DETECTED is not None:
        STALE_TIP_DETECTED.inc()


def record_peer_evicted(reason: str) -> None:
    """Record a peer eviction event.

    Args:
        reason: Why peer was evicted (chain_sync_timeout, extra_outbound)
    """
    if PEER_EVICTIONS is not None:
        PEER_EVICTIONS.labels(reason=reason).inc()


def update_utxo_cache_metrics(
    entries: int, memory_bytes: int, dirty: int, hit_rate: float, flushes: int
) -> None:
    """Update UTXO cache metrics.

    Args:
        entries: Total cache entry count
        memory_bytes: Approximate memory usage in bytes
        dirty: Number of dirty entries (modified since last flush)
        hit_rate: Cache hit rate (0.0-1.0)
        flushes: Total flush count (for incrementing counter)
    """
    if UTXO_CACHE_SIZE is not None:
        UTXO_CACHE_SIZE.set(entries)
    if UTXO_CACHE_MEMORY is not None:
        UTXO_CACHE_MEMORY.set(memory_bytes)
    if UTXO_CACHE_DIRTY is not None:
        UTXO_CACHE_DIRTY.set(dirty)
    if UTXO_CACHE_HIT_RATE is not None:
        UTXO_CACHE_HIT_RATE.set(hit_rate)
    # Note: flushes counter is not incremented here as it tracks lifetime total


def record_utxo_cache_flush() -> None:
    """Record a UTXO cache flush event."""
    if UTXO_CACHE_FLUSHES is not None:
        UTXO_CACHE_FLUSHES.inc()
