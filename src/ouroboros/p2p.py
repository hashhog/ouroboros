"""
Peer-to-peer networking module.

This module implements peer discovery, connection management, and peer scoring
for the Bitcoin P2P network. Includes eclipse attack mitigations:

  - Connection diversification: outbound connections span multiple /16 network groups
  - Anchor connections: persist 2 block-relay-only connections across restarts
  - Feeler connections: periodically probe new addresses to verify them
  - Reserved inbound slots: keep 2 slots for connections from new networks

Reference: Bitcoin Core net.cpp, net_processing.cpp
"""

import asyncio
import base64
import json
import logging
import os
import random
import socket
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field

from ouroboros.addrman import AddressManager, get_network_group
from ouroboros.banman import (
    BanManager,
)
from ouroboros.minisketch import (
    Minisketch,
    ReconciliationSet,
    estimate_sketch_capacity,
)
from ouroboros.p2p_messages import (
    INV_TYPE_TX,
    MSG_WTX,
    AddrMessage,
    AddrV2Message,
    BlockTxnMessage,
    GetAddrMessage,
    GetBlockTxnMessage,
    GetPkgTxnsMessage,
    InvMessage,
    NetworkMessage,
    PkgTxnsMessage,
    ReconcilDiffMessage,
    ReqTxRcnclMessage,
    SendCmpctMessage,
    SendPackagesMessage,
    SendTxRcnclMessage,
    SketchMessage,
    get_magic,
)
from ouroboros.peer import Peer, is_local_addr, is_onion_host
from ouroboros.tor import (
    I2PSession,
    TorController,
    i2p_destination_to_address,
    is_i2p_host,
)

logger = logging.getLogger(__name__)


# BIP 133 Fee Filter constants (Bitcoin Core net_processing.cpp)
# Average delay between feefilter broadcasts
AVG_FEEFILTER_BROADCAST_INTERVAL = 600.0  # 10 minutes
# Maximum delay after significant change
MAX_FEEFILTER_CHANGE_DELAY = 300.0  # 5 minutes
# Fee filter spacing for bucketing (1.1x between buckets)
FEE_FILTER_SPACING = 1.1
# Maximum fee rate for filter
MAX_FILTER_FEERATE = 1e7
# Minimum relay fee rate (sat/kvB)
MIN_RELAY_FEE_RATE = 1000


# BIP 324 v2 fall-back TTL.  An address that fails the v2 ElligatorSwift
# handshake is recorded with the current unix timestamp; subsequent
# outbound connections to the same address within this window dial v1
# directly instead of probing v2 again.  24 h matches Bitcoin Core's
# typical behaviour of remembering v1-only peers across the dialer's
# lifetime; we use a TTL so eventual v2-upgraded peers are re-probed.
V2_FALLBACK_TTL = 86400.0  # seconds


class FeeFilterRounder:
    """Quantize fee rates for privacy before broadcasting.

    Creates discrete fee buckets spaced at 1.1x intervals and rounds
    incoming fees to these buckets with randomization to prevent
    fee-rate fingerprinting.

    Reference: Bitcoin Core policy/fees/block_policy_estimator.cpp
    """

    def __init__(self, min_incremental_fee: int = MIN_RELAY_FEE_RATE):
        """Initialize fee filter rounder.

        Args:
            min_incremental_fee: Minimum fee rate in sat/kvB
        """
        self._fee_set = self._make_fee_set(min_incremental_fee)

    def _make_fee_set(self, min_incremental_fee: int) -> list:
        """Build the set of fee bucket boundaries.

        Creates buckets from min_fee_limit to MAX_FILTER_FEERATE
        with FEE_FILTER_SPACING (1.1x) between each.
        """
        fee_set = [0]
        min_fee_limit = max(1, min_incremental_fee // 2)
        bucket_boundary = float(min_fee_limit)
        while bucket_boundary <= MAX_FILTER_FEERATE:
            fee_set.append(bucket_boundary)
            bucket_boundary *= FEE_FILTER_SPACING
        return sorted(fee_set)

    def round(self, current_min_fee: int) -> int:
        """Quantize a minimum fee for privacy before broadcast.

        Uses randomization: 2/3 of the time rounds down to the previous
        bucket, 1/3 of the time uses the current or higher bucket.
        This adds noise to prevent fee-rate fingerprinting.

        Args:
            current_min_fee: Current minimum fee rate in sat/kvB

        Returns:
            Rounded fee rate in sat/kvB
        """
        if current_min_fee <= 0:
            return 0

        # Find lower_bound (first element >= current_min_fee)
        idx = 0
        for i, fee in enumerate(self._fee_set):
            if fee >= current_min_fee:
                idx = i
                break
        else:
            # current_min_fee exceeds all buckets
            idx = len(self._fee_set)

        # Randomization: 2/3 chance to round down to previous bucket
        if idx == len(self._fee_set) or (idx > 0 and random.randint(0, 2) != 0):
            idx -= 1

        if idx < 0:
            return 0

        return int(self._fee_set[idx])


# Transaction trickling constants (Bitcoin Core net_processing.cpp)
# Average delay between trickled inventory transmissions
INBOUND_INVENTORY_BROADCAST_INTERVAL = 5.0   # seconds (inbound peers)
OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2.0  # seconds (outbound peers)

# Maximum rate of inventory items per second (limits low-fee tx floods)
INVENTORY_BROADCAST_PER_SECOND = 14

# Target number of tx inventory items per transmission
INVENTORY_BROADCAST_TARGET = int(
    INVENTORY_BROADCAST_PER_SECOND * INBOUND_INVENTORY_BROADCAST_INTERVAL
)  # 70 items

# Maximum inventory items per transmission
INVENTORY_BROADCAST_MAX = 1000


@dataclass
class TrickleEntry:
    """Entry in the per-peer trickle queue."""
    txid: bytes               # 32-byte txid
    wtxid: bytes              # 32-byte wtxid (may be same as txid for legacy)
    fee: int = 0              # Transaction fee in satoshis
    vsize: int = 0            # Virtual size in vbytes
    added_time: float = field(default_factory=time.time)

    @property
    def fee_rate_kvb(self) -> int:
        """Fee rate in sat/kvB (sat per 1000 virtual bytes)."""
        if self.vsize <= 0:
            return 0
        return (self.fee * 1000) // self.vsize


class TrickleQueue:
    """Per-peer transaction inventory queue with Poisson-delayed sending.

    Instead of immediately announcing new transactions to all peers, we queue
    INV messages and send them on a randomized schedule. This prevents network
    observers from mapping transactions to their originating IP addresses.

    Bitcoin Core reference: net_processing.cpp
    - INBOUND_INVENTORY_BROADCAST_INTERVAL = 5s
    - OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2s
    - Uses Poisson distribution via rand_exp_duration()
    - Batches up to INVENTORY_BROADCAST_MAX per message
    - Prefers wtxid for BIP339 peers
    """

    def __init__(self, is_inbound: bool = False, wtxid_relay: bool = False):
        """Initialize trickle queue.

        Args:
            is_inbound: True if this is an inbound peer (uses 5s interval)
            wtxid_relay: True if peer supports BIP339 wtxid relay
        """
        self.is_inbound = is_inbound
        self.wtxid_relay = wtxid_relay

        # Set of wtxids pending announcement (like m_tx_inventory_to_send)
        self.pending_wtxids: set[bytes] = set()

        # Map wtxid -> txid for peers that don't support wtxid relay
        self.wtxid_to_txid: dict[bytes, bytes] = {}

        # Map wtxid -> TrickleEntry for fee information (BIP133 feefilter)
        self.wtxid_to_entry: dict[bytes, TrickleEntry] = {}

        # Bloom filter to track already-announced txs (like m_tx_inventory_known_filter)
        # For simplicity, use a set here; Bitcoin Core uses CRollingBloomFilter
        self.known_filter: set[bytes] = set()

        # Next scheduled send time
        self.next_send_time: float = 0.0

        # Average interval for Poisson delay
        self.avg_interval = (
            INBOUND_INVENTORY_BROADCAST_INTERVAL if is_inbound
            else OUTBOUND_INVENTORY_BROADCAST_INTERVAL
        )

    def add_tx(
        self,
        txid: bytes,
        wtxid: bytes,
        fee: int = 0,
        vsize: int = 0,
    ) -> bool:
        """Queue a transaction for trickled announcement.

        Args:
            txid: 32-byte transaction id
            wtxid: 32-byte witness transaction id
            fee: Transaction fee in satoshis (for BIP133 feefilter)
            vsize: Virtual size in vbytes (for BIP133 feefilter)

        Returns:
            True if added, False if already known/pending
        """
        # Check if already known to this peer
        inv_hash = wtxid if self.wtxid_relay else txid
        if inv_hash in self.known_filter:
            return False

        if wtxid in self.pending_wtxids:
            return False

        self.pending_wtxids.add(wtxid)
        self.wtxid_to_txid[wtxid] = txid
        self.wtxid_to_entry[wtxid] = TrickleEntry(
            txid=txid, wtxid=wtxid, fee=fee, vsize=vsize
        )
        return True

    def mark_known(self, txid: bytes, wtxid: bytes) -> None:
        """Mark a transaction as known to this peer (received from them)."""
        inv_hash = wtxid if self.wtxid_relay else txid
        self.known_filter.add(inv_hash)
        # Remove from pending if queued
        self.pending_wtxids.discard(wtxid)
        self.wtxid_to_txid.pop(wtxid, None)
        self.wtxid_to_entry.pop(wtxid, None)

    def should_send(self, current_time: float) -> bool:
        """Check if it's time to send trickled INVs."""
        return current_time >= self.next_send_time and len(self.pending_wtxids) > 0

    def schedule_next_send(self, current_time: float) -> None:
        """Schedule the next send using Poisson-distributed delay.

        Uses random.expovariate() which produces exponentially distributed
        random values, implementing Poisson process timing.
        """
        # Poisson delay: exponential distribution with rate = 1/avg_interval
        delay = random.expovariate(1.0 / self.avg_interval)
        self.next_send_time = current_time + delay

    def get_invs_to_send(
        self,
        max_count: int = INVENTORY_BROADCAST_MAX,
        feefilter: int = 0,
    ) -> list[tuple[int, bytes]]:
        """Get INV items ready to send and remove them from the queue.

        BIP133: Transactions with fee rate below the peer's feefilter
        are skipped (not announced to that peer).

        Args:
            max_count: Maximum number of items to return
            feefilter: Peer's minimum fee rate in sat/kvB (BIP133)

        Returns:
            List of (inv_type, hash) tuples for InvMessage
        """
        # Adaptively scale the broadcast limit based on queue size
        # (Bitcoin Core: INVENTORY_BROADCAST_TARGET + (size/1000)*5)
        broadcast_max = min(
            INVENTORY_BROADCAST_TARGET + (len(self.pending_wtxids) // 1000) * 5,
            max_count,
        )
        broadcast_max = min(broadcast_max, INVENTORY_BROADCAST_MAX)

        # Randomize order for privacy
        pending_list = list(self.pending_wtxids)
        random.shuffle(pending_list)

        inv_items: list[tuple[int, bytes]] = []
        to_remove: list[bytes] = []

        for wtxid in pending_list[:broadcast_max]:
            txid = self.wtxid_to_txid.get(wtxid, wtxid)
            entry = self.wtxid_to_entry.get(wtxid)

            # BIP133: Skip transactions below peer's feefilter threshold
            # Only filter INV announcements, not responses to GETDATA
            # Only filter if we have valid fee info (vsize > 0)
            if feefilter > 0 and entry is not None and entry.vsize > 0:
                if entry.fee_rate_kvb < feefilter:
                    # Don't announce to this peer, but keep in queue
                    # (may be announced later if feefilter drops)
                    continue

            # Choose INV type based on peer's wtxid relay preference
            if self.wtxid_relay:
                inv_type = MSG_WTX  # BIP339: type 5 (wtxid)
                inv_hash = wtxid
            else:
                inv_type = INV_TYPE_TX  # type 1 (txid)
                inv_hash = txid

            # Skip if already known
            if inv_hash in self.known_filter:
                to_remove.append(wtxid)
                continue

            inv_items.append((inv_type, inv_hash))
            self.known_filter.add(inv_hash)
            to_remove.append(wtxid)

        # Remove sent items from pending set
        for wtxid in to_remove:
            self.pending_wtxids.discard(wtxid)
            self.wtxid_to_txid.pop(wtxid, None)
            self.wtxid_to_entry.pop(wtxid, None)

        return inv_items

    @property
    def pending_count(self) -> int:
        """Number of transactions pending announcement."""
        return len(self.pending_wtxids)

    def clear(self) -> None:
        """Clear all pending announcements."""
        self.pending_wtxids.clear()
        self.wtxid_to_txid.clear()
        self.wtxid_to_entry.clear()


# DNS seeds for mainnet
DNS_SEEDS_MAINNET = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
]

# DNS seeds for testnet3
DNS_SEEDS_TESTNET = [
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.org",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
]

# DNS seeds for testnet4 (BIP-94)
DNS_SEEDS_TESTNET4 = [
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz",
]


MAX_INBOUND = 117  # Bitcoin Core default max inbound connections

# Bitcoin Core maintains 2 additional outbound connections that relay only
# blocks (no transactions, no addr gossip).  These protect against eclipse
# attacks by increasing the number of independent peers that can announce
# new blocks to us.
MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2

# Eclipse attack mitigation constants (Bitcoin Core net.h)
MAX_BLOCK_RELAY_ONLY_ANCHORS = 2  # persistent anchor connections across restarts
FEELER_INTERVAL = 120.0  # seconds between feeler connections (2 minutes)
FEELER_SLEEP_WINDOW = 1.0  # jitter window for feeler timing
MAX_FEELER_CONNECTIONS = 1  # only one feeler at a time

# Reserved inbound slots for connections from new /16 groups
# This ensures diverse inbound connections and resists eclipse attacks
RESERVED_INBOUND_SLOTS_FOR_NEW_GROUPS = 2


class PeerManager:
    """Manages peer connections and discovery"""

    def __init__(
        self,
        network: str = "mainnet",
        max_peers: int = 8,
        max_block_relay_only: int = MAX_BLOCK_RELAY_ONLY_CONNECTIONS,
        data_dir: str | None = None,
        transport_version: int = 1,
        listen: bool = True,
        proxy: str | None = None,
        onion: str | None = None,
        i2psam: str | None = None,
        torcontrol: str | None = None,
        torpassword: str | None = None,
        peer_bloom_filters: bool = False,
        node_compact_filters: bool = False,
        node_network_limited: bool = False,
    ):
        """Initialize peer manager."""
        self.network = network
        self.max_peers = max_peers
        self.max_block_relay_only = max_block_relay_only
        self.transport_version = transport_version
        self._listen_enabled = listen
        self.proxy = proxy    # global SOCKS5 proxy for all outbound
        self.onion = onion    # SOCKS5 proxy specifically for .onion peers
        self.i2psam = i2psam  # I2P SAM bridge (host:port)
        self.torcontrol = torcontrol  # Tor control port (host:port)
        self.torpassword = torpassword  # Tor control password
        # BIP 111 NODE_BLOOM advertisement (Core parity: -peerbloomfilters,
        # default false).  Forwarded to every Peer constructed here so the
        # version handshakes (inbound + outbound) and BIP-35 MEMPOOL gate
        # see a consistent value.
        self.peer_bloom_filters = peer_bloom_filters
        # BIP 157 NODE_COMPACT_FILTERS advertisement (Core parity:
        # -blockfilterindex, default false).  Forwarded to every Peer so
        # the version handshakes advertise the bit only when the index is
        # actually enabled at the node level.
        self.node_compact_filters = node_compact_filters
        # BIP-159 NODE_NETWORK_LIMITED advertisement (Core parity:
        # `IsPruneMode()` gate in init.cpp).  Set when prune mode is on
        # (`prune > 0` in node config).  Forwarded to every Peer so the
        # version handshakes advertise the bit only when we actually
        # serve only the recent ~288-block window.
        self.node_network_limited = node_network_limited

        self.peers: dict[str, Peer] = {}  # addr -> Peer (full-relay outbound)
        self.block_relay_peers: dict[str, Peer] = {}  # addr -> Peer (block-relay-only outbound)
        self.inbound_peers: dict[str, Peer] = {}  # addr -> Peer (inbound)
        self.known_addrs: set[str] = set()

        self.ban_manager = BanManager(
            data_dir=data_dir,
            on_ban=self._on_peer_banned,
        )

        # Connection retry tracking (addr -> retry_count)
        self.retry_counts: dict[str, int] = defaultdict(int)
        self.last_retry_time: dict[str, float] = {}

        # BIP 324 v2 fall-back state.  When an outbound v2 handshake
        # fails for an address we record a unix-timestamp here so
        # subsequent connection attempts within ``V2_FALLBACK_TTL``
        # seconds skip the v2 probe and dial directly with v1.  This
        # mirrors Bitcoin Core's m_reconnections queue (net.cpp:1949)
        # except as a TTL cache rather than a one-shot list — ouroboros
        # does not have Core's 1:1 reconnect-pump architecture.
        self._v1_only_addrs: dict[str, float] = {}

        self.running = False
        self._maintenance_task: asyncio.Task | None = None
        self._server: asyncio.AbstractServer | None = None
        self._start_height: int = 0

        # Callback for registering handlers on newly accepted inbound peers
        self._on_inbound_peer: asyncio.coroutines | None = None

        # Callback for registering handlers on newly dialed outbound peers.
        # Invoked from every outbound success site (full-relay, block-relay,
        # anchor, feeler, addnode) so the node can wire up tx / getdata /
        # getheaders handlers symmetrically to inbound peers.  Without this
        # hook, post-startup outbound peers silently drop those messages —
        # the node could IBD but could not serve the remote side's queries.
        self._on_outbound_peer: asyncio.coroutines | None = None

        # Address manager for peer gossip
        self.addrman = AddressManager(data_dir=data_dir)

        # Per-peer rate limiting for addr relay (addr -> last relay epoch)
        self._addr_relay_counts: dict[str, int] = defaultdict(int)
        self._addr_relay_day: dict[str, float] = {}

        # BIP 152 compact-block state
        self.compact_block_version: int = 2
        self.cmpct_peers: set[str] = set()
        self._mempool = None
        self._on_compact_block = None
        self._database = None  # database for block lookups (getblocktxn)
        # In-flight partial compact blocks: block_hash -> (CompactBlock, partial_txs)
        # where partial_txs is a list with None slots for missing transactions.
        # Populated by on_cmpctblock when some txs are absent from mempool;
        # consumed and cleared by on_blocktxn after the round-trip completes.
        # Mirrors Bitcoin Core's PartiallyDownloadedBlock per-peer state
        # (blockencodings.h / net_processing.cpp ProcessMessage "blocktxn").
        self._partial_cmpct_blocks: dict = {}  # bytes -> (CompactBlock, list)

        # BIP 330 Erlay reconciliation state
        self.erlay_enabled: bool = True  # whether we support Erlay
        self._erlay_peers: dict[str, ReconciliationSet] = {}  # addr -> recon set
        self._erlay_local_salts: dict[str, int] = {}  # addr -> our salt
        self._erlay_pending_recon: dict[str, bool] = {}  # addr -> recon in progress
        self._reconciliation_task: asyncio.Task | None = None
        self._reconciliation_interval: float = 2.0  # seconds between rounds

        # BIP 331 package relay state.
        # ``package_relay_enabled`` is the local advertisement flag — when
        # True we send ``sendpackages`` post-handshake.  ``_package_peers``
        # is the set of addrs that completed the bidirectional handshake
        # (both sides sent sendpackages).
        self.package_relay_enabled: bool = True
        self.package_relay_version: int = 1
        self.package_max_count: int = 25       # MAX_PACKAGE_COUNT
        self.package_max_weight: int = 404_000  # MAX_PACKAGE_WEIGHT
        self._package_peers: set[str] = set()

        # Transaction trickling state (privacy-preserving relay)
        # Per-peer trickle queues: addr -> TrickleQueue
        self._trickle_queues: dict[str, TrickleQueue] = {}
        self._trickle_task: asyncio.Task | None = None
        self._trickle_interval: float = 1.0  # check interval in seconds

        # Eclipse attack mitigation state
        # Anchor connections: persistent block-relay-only peers across restarts
        self._anchors: list[str] = []  # list of anchor addresses
        self._anchors_filepath: str | None = None
        if data_dir:
            self._anchors_filepath = os.path.join(data_dir, "anchors.dat")
            self._load_anchors()

        # Feeler connections: probe new addresses periodically
        self._feeler_task: asyncio.Task | None = None
        self._feeler_peer: Peer | None = None
        self._next_feeler_time: float = 0.0

        # ASMap health-check periodic task (FIX-52)
        self._asmap_health_task: asyncio.Task | None = None
        self._asmap_health_interval: int = 3600  # seconds (configurable)

        # Track outbound /16 groups for connection diversification
        self._outbound_netgroups: set[str] = set()

        # Track outbound ASNs for ASN-diversity enforcement (FIX-51).
        # Populated when addrman has an asmap loaded; empty otherwise.
        self._outbound_asns: set[int] = set()

        # Track inbound /16 groups for reserved slot enforcement
        self._inbound_netgroups: dict[str, int] = {}  # group -> count

        # Tor hidden service support
        self._tor_controller: TorController | None = None
        self._tor_onion_address: str | None = None
        self._data_dir = data_dir

        # I2P SAM session
        self._i2p_session: I2PSession | None = None
        self._i2p_address: str | None = None
        self._i2p_accept_task: asyncio.Task | None = None

        # Persistent --connect peers that should be reconnected when lost
        self._connect_addrs: list[tuple[str, int]] = []

    async def start(self, start_height: int = 0, p2p_port: int = 0):
        """
        Start peer manager.

        Args:
            start_height: Our blockchain height for version messages
            p2p_port: Port to listen on for inbound connections (0 = default)
        """
        if self.running:
            logger.warning("PeerManager already running")
            return

        self.running = True
        self._start_height = start_height
        logger.info(f"Starting PeerManager for {self.network} (max_peers={self.max_peers})")

        # Start listening for inbound connections
        if self._listen_enabled and p2p_port:
            await self._start_listening(p2p_port)

            # Start Tor hidden service for inbound .onion connections
            if self.torcontrol:
                await self._start_tor_hidden_service(p2p_port)

            # Start I2P SAM session for inbound/outbound I2P connections
            if self.i2psam:
                await self._start_i2p_session(p2p_port)

        # Discover peers from DNS seeds
        await self.discover_peers()

        # Connect to anchor peers first (eclipse protection)
        await self._connect_anchor_peers(start_height)

        # Connect to full-relay outbound peers
        await self.connect_to_peers(start_height)

        # Connect to block-relay-only outbound peers
        await self._connect_block_relay_peers(start_height)

        # Start maintenance task
        self._maintenance_task = asyncio.create_task(
            self.maintain_connections(start_height)
        )

        # Start Erlay reconciliation loop
        if self.erlay_enabled:
            self._reconciliation_task = asyncio.create_task(
                self._reconciliation_loop()
            )

        # Start transaction trickle loop
        self._trickle_task = asyncio.create_task(self._trickle_loop())

        # Start feeler connection loop (eclipse protection)
        self._feeler_task = asyncio.create_task(self._feeler_loop())

        # Log initial ASMap health and start periodic health-check task (FIX-52)
        if self.addrman.using_asmap():
            hc = self.addrman.asmap_health_check()
            logger.info(
                "[asmap] Loaded: %d addrs, %d mapped, %d unmapped, %d unique ASNs. "
                "Top ASNs: %s",
                hc["total_addrs"],
                hc["mapped"],
                hc["unmapped"],
                hc["unique_asns"],
                hc["top_asns"],
            )
        self._asmap_health_task = asyncio.create_task(self._asmap_health_loop())

    async def stop(self):
        """Stop peer manager and disconnect all peers"""
        if not self.running:
            return

        logger.info("Stopping PeerManager...")
        self.running = False

        # Stop listening server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel maintenance task
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass

        # Cancel reconciliation task
        if self._reconciliation_task:
            self._reconciliation_task.cancel()
            try:
                await self._reconciliation_task
            except asyncio.CancelledError:
                pass

        # Cancel trickle task
        if self._trickle_task:
            self._trickle_task.cancel()
            try:
                await self._trickle_task
            except asyncio.CancelledError:
                pass

        # Cancel feeler task
        if self._feeler_task:
            self._feeler_task.cancel()
            try:
                await self._feeler_task
            except asyncio.CancelledError:
                pass

        # Cancel ASMap health-check task (FIX-52)
        if self._asmap_health_task:
            self._asmap_health_task.cancel()
            try:
                await self._asmap_health_task
            except asyncio.CancelledError:
                pass

        # Disconnect feeler peer if active
        if self._feeler_peer and self._feeler_peer.is_connected():
            await self._feeler_peer.disconnect()
            self._feeler_peer = None

        # Cancel I2P accept task
        if self._i2p_accept_task:
            self._i2p_accept_task.cancel()
            try:
                await self._i2p_accept_task
            except asyncio.CancelledError:
                pass

        # Stop Tor hidden service
        if self._tor_controller:
            await self._tor_controller.remove_hidden_service()
            await self._tor_controller.disconnect()
            self._tor_controller = None
            self._tor_onion_address = None

        # Stop I2P session
        if self._i2p_session:
            await self._i2p_session.disconnect()
            self._i2p_session = None
            self._i2p_address = None

        # Save anchor connections before shutting down
        self._save_anchors()

        # Disconnect all peers (full-relay + block-relay-only + inbound)
        all_peers = (
            list(self.peers.values())
            + list(self.block_relay_peers.values())
            + list(self.inbound_peers.values())
        )
        disconnect_tasks = [peer.disconnect() for peer in all_peers]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)

        self.peers.clear()
        self.block_relay_peers.clear()
        self.inbound_peers.clear()

        # Persist address manager
        self.addrman.save()

        logger.info("PeerManager stopped")

    # Inbound eviction logic

    @staticmethod
    def _netgroup(host: str) -> str:
        """Get /16 network group for connection diversity."""
        return get_network_group(host)

    def _select_eviction_candidate(self) -> str | None:
        """Select the worst inbound peer for eviction."""
        # Build candidate list: [(addr, peer), ...]
        candidates = [
            (addr, peer) for addr, peer in self.inbound_peers.items()
            if peer.is_connected()
        ]

        if not candidates:
            return None

        # Step 2 — Protect 4 with lowest latency
        # Peers with latency == 0 haven't been measured yet; sort them last.
        candidates.sort(
            key=lambda ap: ap[1].latency if ap[1].latency > 0 else float("inf")
        )
        candidates = candidates[4:]  # remove the 4 best-latency peers

        if not candidates:
            return None

        # Step 3 — Protect 4 with highest score (proxy for upload volume)
        candidates.sort(key=lambda ap: ap[1].score, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 4 — Protect 4 with most recent block relay activity
        candidates.sort(key=lambda ap: ap[1].last_block_time, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 5 — Protect up to 4 from unique /16 netgroups
        seen_groups: set = set()
        protected_netgroup: list = []
        for addr, peer in candidates:
            group = self._netgroup(peer.host)
            if group not in seen_groups and len(protected_netgroup) < 4:
                seen_groups.add(group)
                protected_netgroup.append(addr)
        candidates = [
            (a, p) for a, p in candidates if a not in protected_netgroup
        ]

        if not candidates:
            return None

        # Step 6 — Protect 4 most recently connected
        candidates.sort(key=lambda ap: ap[1].connected_at, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 7 — From remaining, evict the one connected longest
        candidates.sort(key=lambda ap: ap[1].connected_at)
        return candidates[0][0]

    async def _evict_inbound_peer(self) -> bool:
        victim_addr = self._select_eviction_candidate()
        if victim_addr is None:
            return False

        victim = self.inbound_peers.pop(victim_addr, None)
        if victim is not None:
            logger.info(f"Evicting inbound peer {victim_addr} to make room")
            await victim.disconnect()
            return True
        return False

    # Inbound connection handling

    async def _start_listening(self, port: int):
        try:
            self._server = await asyncio.start_server(
                self._handle_inbound_connection,
                host="0.0.0.0",
                port=port,
            )
            logger.info(f"Listening for inbound connections on port {port}")
        except OSError as e:
            logger.warning(f"Failed to listen on port {port}: {e}")

    async def _handle_inbound_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Callback for each new inbound TCP connection."""
        peername = writer.get_extra_info("peername")
        if not peername:
            writer.close()
            return
        host, port = peername[0], peername[1]
        addr = f"{host}:{port}"

        # Check ban list
        if self.ban_manager.is_banned(host) or self.ban_manager.is_banned(addr):
            logger.debug(f"Rejected banned inbound peer {addr}")
            writer.close()
            return

        # Eclipse protection: reserved slots for new network groups
        peer_group = self._netgroup(host)
        is_new_group = peer_group not in self._inbound_netgroups

        # Calculate effective limit (reserve slots for new groups)
        effective_limit = MAX_INBOUND
        if not is_new_group:
            # Not a new group - reduce limit by reserved slots
            effective_limit = MAX_INBOUND - RESERVED_INBOUND_SLOTS_FOR_NEW_GROUPS

        # Check inbound limit — try to evict the worst peer first
        if len(self.inbound_peers) >= effective_limit:
            if not await self._evict_inbound_peer():
                logger.debug(f"Rejected inbound peer {addr}: max inbound reached, no eviction candidate")
                writer.close()
                return

        logger.info(f"New inbound connection from {addr} (netgroup={peer_group})")

        # Inbound peers honour the manager's configured transport_version
        # so that BIP 324 v2 detection runs in accept_inbound.  When the
        # manager is v1-only (transport_version == 1), this short-circuits
        # the peek+classify path and the legacy v1 handshake runs unchanged.
        peer = Peer(host, port, self.network,
                    transport_version=self.transport_version,
                    inbound=True,
                    ban_manager=self.ban_manager,
                    peer_bloom_filters=self.peer_bloom_filters,
                    node_compact_filters=self.node_compact_filters,
                    node_network_limited=self.node_network_limited)
        if await peer.accept_inbound(reader, writer, self._start_height):
            self.inbound_peers[addr] = peer
            self._register_compact_handlers(peer, addr)
            self._register_bloom_handlers(peer, addr)
            self._register_addr_handlers(peer, addr)
            asyncio.ensure_future(self.negotiate_compact_blocks(peer))
            # Negotiate Erlay for inbound peers
            if self.erlay_enabled:
                self._register_erlay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_erlay(peer, addr))
            # Negotiate BIP 331 package relay for inbound peers
            if self.package_relay_enabled:
                self._register_package_relay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_package_relay(peer))
            # Initialize trickle queue for inbound peer (5s avg delay)
            self._trickle_queues[addr] = TrickleQueue(
                is_inbound=True, wtxid_relay=peer.wtxid_relay
            )

            # Track inbound netgroup for eclipse protection
            self._inbound_netgroups[peer_group] = self._inbound_netgroups.get(peer_group, 0) + 1

            # Notify node so it can register tx/getdata handlers
            if self._on_inbound_peer:
                try:
                    await self._on_inbound_peer(peer)
                except Exception as e:
                    logger.error(f"Error in inbound peer callback: {e}")

            logger.info(
                f"Inbound peer {addr} ready "
                f"({len(self.inbound_peers)} inbound, {len(self._inbound_netgroups)} groups)"
            )

    def set_inbound_peer_handler(self, handler) -> None:
        """Register an async callback invoked when an inbound peer completes
        its handshake.  ``handler(peer: Peer) -> None``."""
        self._on_inbound_peer = handler

    def set_outbound_peer_handler(self, handler) -> None:
        """Register an async callback invoked when an outbound peer completes
        its handshake.  ``handler(peer: Peer) -> None``.

        Mirrors :meth:`set_inbound_peer_handler` for outbound dials.  Used
        by ``Node`` to register tx / getdata / getheaders handlers on every
        outbound peer (full-relay, block-relay-only, anchor, feeler) so we
        actually serve the peer's queries instead of silently ignoring them.
        """
        self._on_outbound_peer = handler

    async def _fire_outbound_peer_callback(self, peer: "Peer") -> None:
        """Invoke the outbound-peer handler if one is registered.

        Best-effort: a callback exception is logged but does not fail the
        connection (the peer is already past handshake at this point).
        """
        if self._on_outbound_peer is None:
            return
        try:
            await self._on_outbound_peer(peer)
        except Exception as e:
            logger.error(f"Error in outbound peer callback: {e}")

    # Eclipse protection: anchor connections

    def _load_anchors(self) -> None:
        """Load anchor addresses from disk."""
        if not self._anchors_filepath or not os.path.exists(self._anchors_filepath):
            return
        try:
            with open(self._anchors_filepath) as f:
                data = json.load(f)
            self._anchors = data.get("anchors", [])[:MAX_BLOCK_RELAY_ONLY_ANCHORS]
            logger.info(f"Loaded {len(self._anchors)} anchor connections")
        except Exception as e:
            logger.warning(f"Failed to load anchors: {e}")

    def _save_anchors(self) -> None:
        """Save current block-relay-only peers as anchors for next restart."""
        if not self._anchors_filepath:
            return
        try:
            # Use current block-relay-only peers as anchors
            anchors = list(self.block_relay_peers.keys())[:MAX_BLOCK_RELAY_ONLY_ANCHORS]
            data = {"anchors": anchors, "saved_at": time.time()}
            tmp = self._anchors_filepath + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self._anchors_filepath)
            logger.debug(f"Saved {len(anchors)} anchor connections")
        except Exception as e:
            logger.warning(f"Failed to save anchors: {e}")

    async def _connect_anchor_peers(self, start_height: int) -> None:
        """Connect to anchor peers from previous session.

        Anchor connections are block-relay-only peers that persist across
        restarts, providing continuity against eclipse attacks.
        """
        if not self._anchors:
            return

        logger.info(f"Connecting to {len(self._anchors)} anchor peers...")
        for addr in self._anchors:
            if len(self.block_relay_peers) >= self.max_block_relay_only:
                break
            if addr in self._all_outbound_addrs():
                continue
            if self.ban_manager.is_banned(addr):
                continue

            try:
                host, port = addr.split(":")
                port = int(port)
            except ValueError:
                continue

            peer_proxy = self._proxy_for_host(host)
            if is_onion_host(host) and not peer_proxy:
                continue

            peer = await self._dial_outbound(
                host, port,
                relay_txs=False,  # block-relay-only
                start_height=start_height,
                retry=True,
            )

            if peer is not None:
                self.block_relay_peers[addr] = peer
                self.addrman.mark_good(host, port)
                group = self._netgroup(host)
                self._outbound_netgroups.add(group)
                self._register_compact_handlers(peer, addr)
                self._register_bloom_handlers(peer, addr)
                # Fire outbound-peer hook so the node can attach tx /
                # getdata / getheaders handlers to this anchor peer.
                asyncio.ensure_future(self._fire_outbound_peer_callback(peer))
                logger.info(f"Connected to anchor peer {addr}")
            else:
                self.addrman.mark_attempt(host, port)

    # Eclipse protection: feeler connections

    async def _asmap_health_loop(self) -> None:
        """Background loop that logs ASMap health statistics every hour (FIX-52).

        Runs every ``self._asmap_health_interval`` seconds (default 3600).
        When no asmap is loaded the loop sleeps but remains alive so it can
        start reporting if an asmap is loaded at runtime in the future.

        Mirrors the kind of periodic diagnostics Bitcoin Core would emit
        for addrman / ASMap health monitoring.
        """
        try:
            while self.running:
                await asyncio.sleep(self._asmap_health_interval)
                if not self.running:
                    break
                try:
                    hc = self.addrman.asmap_health_check()
                    if hc["asmap_active"]:
                        logger.info(
                            "[asmap] Health: %d addrs, %d mapped (%.1f%%), "
                            "%d unmapped, %d unique ASNs. Top ASNs: %s",
                            hc["total_addrs"],
                            hc["mapped"],
                            100.0 * hc["mapped"] / max(hc["total_addrs"], 1),
                            hc["unmapped"],
                            hc["unique_asns"],
                            hc["top_asns"],
                        )
                    else:
                        logger.debug("[asmap] No asmap loaded — health check skipped")
                except Exception as e:
                    logger.warning("[asmap] Health check error: %s", e)
        except asyncio.CancelledError:
            logger.debug("ASMap health loop cancelled")
        except Exception as e:
            logger.error("Error in ASMap health loop: %s", e)

    async def _feeler_loop(self) -> None:
        """Background loop that makes feeler connections to verify new addresses.

        Feelers are short-lived connections that probe addresses from the new
        table to verify they're real and reachable. This helps detect bad
        addresses before they're moved to the tried table.
        """
        try:
            # Initial delay with jitter
            self._next_feeler_time = time.time() + random.expovariate(1.0 / FEELER_INTERVAL)

            while self.running:
                await asyncio.sleep(1.0)
                if not self.running:
                    break

                now = time.time()
                if now < self._next_feeler_time:
                    continue

                # Schedule next feeler with exponential random interval
                self._next_feeler_time = now + random.expovariate(1.0 / FEELER_INTERVAL)
                self._next_feeler_time += random.uniform(0, FEELER_SLEEP_WINDOW)

                # Make feeler connection
                await self._make_feeler_connection()

        except asyncio.CancelledError:
            logger.debug("Feeler loop cancelled")
        except Exception as e:
            logger.error(f"Error in feeler loop: {e}")

    async def _make_feeler_connection(self) -> None:
        """Make a single feeler connection to probe a new address."""
        # Don't make multiple feelers simultaneously
        if self._feeler_peer and self._feeler_peer.is_connected():
            return

        # Select address from new table for probing
        exclude = self._all_outbound_addrs() | set(self.inbound_peers.keys())
        addr = self.addrman.select_for_feeler(exclude=exclude)
        if not addr:
            return

        try:
            host, port = addr.split(":")
            port = int(port)
        except ValueError:
            return

        peer_proxy = self._proxy_for_host(host)
        if is_onion_host(host) and not peer_proxy:
            return

        logger.debug(f"Making feeler connection to {addr}")

        self.addrman.mark_attempt(host, port)
        # _dial_outbound handles v2-first + v1 fall-back transparently.
        # We pre-set _feeler_peer to a sentinel so concurrent feeler
        # calls see "in flight" via is_connected() check at entry.
        peer = await self._dial_outbound(
            host, port,
            relay_txs=False,  # feelers don't relay
            start_height=self._start_height,
            retry=False,
        )
        self._feeler_peer = peer

        if peer is not None:
            # Successful - mark as good and disconnect
            self.addrman.mark_good(host, port)
            logger.debug(f"Feeler to {addr} succeeded, moving to tried table")
            await peer.disconnect()
        else:
            # Failed - mark as failed
            self.addrman.mark_failed(host, port)
            logger.debug(f"Feeler to {addr} failed")

        self._feeler_peer = None

    # --- Tor Hidden Service Support ---

    async def _start_tor_hidden_service(self, p2p_port: int) -> None:
        """Start Tor hidden service for accepting inbound .onion connections.

        Creates an ephemeral hidden service via Tor control protocol that
        forwards incoming connections to our P2P port.
        """
        if not self.torcontrol:
            return

        try:
            # Parse control address
            parts = self.torcontrol.rsplit(":", 1)
            if len(parts) == 2:
                control_host, control_port = parts[0], int(parts[1])
            else:
                control_host, control_port = self.torcontrol, 9051

            self._tor_controller = TorController(
                control_host=control_host,
                control_port=control_port,
                password=self.torpassword,
                data_dir=self._data_dir,
            )

            if await self._tor_controller.connect():
                self._tor_onion_address = await self._tor_controller.create_hidden_service(
                    target_port=p2p_port
                )
                if self._tor_onion_address:
                    logger.info(f"Tor hidden service ready: {self._tor_onion_address}:{p2p_port}")
                else:
                    logger.warning("Failed to create Tor hidden service")
            else:
                logger.warning("Failed to connect to Tor control port")
                self._tor_controller = None

        except Exception as e:
            logger.error(f"Error starting Tor hidden service: {e}")
            self._tor_controller = None

    # --- I2P SAM Support ---

    async def _start_i2p_session(self, p2p_port: int) -> None:
        """Start I2P SAM session for anonymous P2P connections.

        Creates a streaming session that can both make outbound connections
        and accept inbound connections via I2P.
        """
        if not self.i2psam:
            return

        try:
            # Parse SAM address
            parts = self.i2psam.rsplit(":", 1)
            if len(parts) == 2:
                sam_host, sam_port = parts[0], int(parts[1])
            else:
                sam_host, sam_port = self.i2psam, 7656

            self._i2p_session = I2PSession(
                sam_host=sam_host,
                sam_port=sam_port,
                data_dir=self._data_dir,
                persistent=True,
            )

            if await self._i2p_session.connect():
                self._i2p_address = self._i2p_session.address
                logger.info(f"I2P session ready: {self._i2p_address}")

                # Start accepting inbound I2P connections
                self._i2p_accept_task = asyncio.create_task(
                    self._i2p_accept_loop(p2p_port)
                )
            else:
                logger.warning("Failed to connect to I2P SAM bridge")
                self._i2p_session = None

        except Exception as e:
            logger.error(f"Error starting I2P session: {e}")
            self._i2p_session = None

    async def _i2p_accept_loop(self, p2p_port: int) -> None:
        """Background loop accepting incoming I2P connections."""
        try:
            while self.running and self._i2p_session:
                try:
                    result = await self._i2p_session.stream_accept(timeout=60.0)
                    if result is None:
                        continue

                    reader, writer, peer_dest = result
                    # Convert destination to .b32.i2p address for identification
                    peer_addr = i2p_destination_to_address(
                        __import__('base64').b64decode(
                            peer_dest.replace("-", "+").replace("~", "/")
                        )
                    ) if peer_dest != "unknown" else "unknown.b32.i2p"

                    addr = f"{peer_addr}:{p2p_port}"
                    logger.info(f"Accepted I2P connection from {addr}")

                    # Handle like a normal inbound connection
                    await self._handle_i2p_inbound(reader, writer, peer_addr, p2p_port)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning(f"I2P accept error: {e}")
                    await asyncio.sleep(1.0)

        except asyncio.CancelledError:
            logger.debug("I2P accept loop cancelled")
        except Exception as e:
            logger.error(f"I2P accept loop error: {e}")

    async def _handle_i2p_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Handle an incoming I2P connection."""
        addr = f"{host}:{port}"

        # Check inbound limit
        if len(self.inbound_peers) >= MAX_INBOUND:
            if not await self._evict_inbound_peer():
                logger.debug(f"Rejected I2P peer {addr}: max inbound reached")
                writer.close()
                return

        peer = Peer(host, port, self.network,
                    transport_version=self.transport_version,
                    inbound=True,
                    ban_manager=self.ban_manager,
                    peer_bloom_filters=self.peer_bloom_filters,
                    node_compact_filters=self.node_compact_filters,
                    node_network_limited=self.node_network_limited)
        if await peer.accept_inbound(reader, writer, self._start_height):
            self.inbound_peers[addr] = peer
            self._register_compact_handlers(peer, addr)
            self._register_bloom_handlers(peer, addr)
            self._register_addr_handlers(peer, addr)
            asyncio.ensure_future(self.negotiate_compact_blocks(peer))

            if self.erlay_enabled:
                self._register_erlay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_erlay(peer, addr))

            if self.package_relay_enabled:
                self._register_package_relay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_package_relay(peer))

            self._trickle_queues[addr] = TrickleQueue(
                is_inbound=True, wtxid_relay=peer.wtxid_relay
            )

            # Track I2P as its own network group
            peer_group = "i2p"
            self._inbound_netgroups[peer_group] = self._inbound_netgroups.get(peer_group, 0) + 1

            if self._on_inbound_peer:
                try:
                    await self._on_inbound_peer(peer)
                except Exception as e:
                    logger.error(f"Error in inbound peer callback: {e}")

            logger.info(f"I2P peer {addr} ready ({len(self.inbound_peers)} inbound)")

    async def _connect_via_i2p(
        self,
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Connect to an I2P peer via SAM session."""
        if not self._i2p_session or not self._i2p_session.is_connected:
            return None

        try:
            reader, writer = await self._i2p_session.stream_connect(
                dest_address=host,
                timeout=180.0,
            )
            return reader, writer
        except Exception as e:
            logger.debug(f"I2P connect to {host} failed: {e}")
            return None

    async def discover_peers(self):
        """Discover peers from DNS seeds"""
        logger.info("Discovering peers from DNS seeds...")

        seeds = (
            DNS_SEEDS_MAINNET if self.network == "mainnet"
            else DNS_SEEDS_TESTNET4 if self.network == "testnet4"
            else DNS_SEEDS_TESTNET if self.network in ("testnet", "testnet3")
            else []
        )

        if not seeds:
            logger.warning(f"No DNS seeds configured for {self.network}")
            return

        port = (
            8333 if self.network == "mainnet"
            else 48333 if self.network == "testnet4"
            else 18333
        )

        # Resolve DNS seeds in parallel
        tasks = [self._resolve_dns_seed(seed, port) for seed in seeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_discovered = 0
        for seed, result in zip(seeds, results, strict=False):
            if isinstance(result, Exception):
                logger.warning(f"Failed to resolve {seed}: {result}")
            else:
                count = result
                total_discovered += count
                logger.info(f"Discovered {count} peers from {seed}")

        logger.info(f"Total known peers: {len(self.known_addrs)}")

    async def _resolve_dns_seed(self, seed: str, port: int) -> int:
        """Resolve DNS seed and add addresses to known_addrs."""
        try:
            # Use asyncio to resolve DNS (non-blocking)
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(
                seed,
                port,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )

            count = 0
            for addr_info in addrs:
                ip = addr_info[4][0]
                addr = f"{ip}:{port}"
                if not self.ban_manager.is_banned(addr):
                    self.known_addrs.add(addr)
                    self.addrman.add(ip, port, source=seed)
                    count += 1

            return count

        except Exception as e:
            logger.debug(f"Error resolving {seed}: {e}")
            return 0

    def _proxy_for_host(self, host: str) -> str | None:
        """Get SOCKS5 proxy for a host, if any.

        - .onion addresses use the onion proxy (or global proxy)
        - .i2p addresses return None (use I2P SAM instead)
        - Other addresses use the global proxy
        """
        if is_onion_host(host):
            return self.onion or self.proxy
        if is_i2p_host(host):
            return None  # I2P uses SAM, not SOCKS5
        return self.proxy

    def _can_connect_to(self, host: str) -> bool:
        """Check if we can connect to a host.

        For .onion: need a SOCKS5 proxy
        For .i2p: need an I2P SAM session
        For clearnet: always possible (direct or via proxy)
        """
        if is_onion_host(host):
            return bool(self.onion or self.proxy)
        if is_i2p_host(host):
            return self._i2p_session is not None and self._i2p_session.is_connected
        return True

    def _all_outbound_addrs(self) -> set[str]:
        return set(self.peers.keys()) | set(self.block_relay_peers.keys())

    def _update_outbound_netgroups(self) -> None:
        """Rebuild the set of outbound network groups (and ASNs) from current peers."""
        self._outbound_netgroups = set()
        self._outbound_asns = set()
        for peer in self.peers.values():
            self._outbound_netgroups.add(self._netgroup(peer.host))
            if self.addrman.using_asmap():
                asn = self.addrman.get_mapped_as(
                    peer.host, getattr(peer, 'network_id', 1)
                )
                if asn > 0:
                    self._outbound_asns.add(asn)
        for peer in self.block_relay_peers.values():
            self._outbound_netgroups.add(self._netgroup(peer.host))
            if self.addrman.using_asmap():
                asn = self.addrman.get_mapped_as(
                    peer.host, getattr(peer, 'network_id', 1)
                )
                if asn > 0:
                    self._outbound_asns.add(asn)

    # BIP 324 v2 transport fall-back tracking
    # See V2_FALLBACK_TTL.  A peer that failed the outbound v2
    # ElligatorSwift handshake is dialed v1 directly until the TTL
    # expires.

    def _is_v1_only_addr(self, addr: str) -> bool:
        """Return True if *addr* is currently flagged as v1-only.

        Removes stale entries (older than ``V2_FALLBACK_TTL``) lazily.
        """
        ts = self._v1_only_addrs.get(addr)
        if ts is None:
            return False
        if time.time() - ts > V2_FALLBACK_TTL:
            self._v1_only_addrs.pop(addr, None)
            return False
        return True

    def _mark_v1_only(self, addr: str) -> None:
        """Record that *addr* failed v2 negotiation; subsequent retries
        within ``V2_FALLBACK_TTL`` will dial v1 directly."""
        self._v1_only_addrs[addr] = time.time()
        logger.info(
            f"BIP 324: marking {addr} v1-only for {V2_FALLBACK_TTL:.0f}s"
        )

    def _transport_for(self, addr: str) -> int:
        """Return the transport version we should use to dial *addr*.

        Honours the per-address v1-only fall-back cache so we don't
        re-probe v2 against peers we already know speak v1.
        """
        if self.transport_version == 2 and self._is_v1_only_addr(addr):
            return 1
        return self.transport_version

    async def _dial_outbound(
        self,
        host: str,
        port: int,
        *,
        relay_txs: bool,
        start_height: int,
        retry: bool = False,
    ) -> Peer | None:
        """Dial an outbound peer with BIP 324 v2-first + v1 fall-back.

        Returns the connected ``Peer`` on success, or ``None`` on
        failure.  When the v2 ElligatorSwift handshake fails (peer is
        v1-only or the TCP stream got out of sync) the address is
        recorded in ``_v1_only_addrs`` and an immediate fresh-socket
        retry is performed with ``transport_version=1``.

        Centralises the transport-negotiation policy so all outbound
        construction sites (full-relay, block-relay-only, anchor,
        feeler, manual addnode) get identical behaviour.
        """
        addr = f"{host}:{port}"
        peer_proxy = self._proxy_for_host(host)
        attempt_v2 = self._transport_for(addr) == 2

        # First attempt: v2 if configured-and-not-fallback-flagged,
        # otherwise v1.
        peer = Peer(
            host, port, self.network,
            transport_version=2 if attempt_v2 else 1,
            relay_txs=relay_txs,
            proxy=peer_proxy,
            ban_manager=self.ban_manager,
            peer_bloom_filters=self.peer_bloom_filters,
            node_compact_filters=self.node_compact_filters,
            node_network_limited=self.node_network_limited,
        )
        ok = await peer.connect(start_height, retry=retry)
        if ok:
            return peer

        # If the failure was specifically a v2-handshake failure, mark
        # the address v1-only and immediately retry with v1 on a fresh
        # socket.  This matches Bitcoin Core's m_reconnections flow
        # (net.cpp:1949) at a per-dial granularity.
        if attempt_v2 and getattr(peer, "v2_negotiation_failed", False):
            self._mark_v1_only(addr)
            v1_peer = Peer(
                host, port, self.network,
                transport_version=1,
                relay_txs=relay_txs,
                proxy=peer_proxy,
                ban_manager=self.ban_manager,
                peer_bloom_filters=self.peer_bloom_filters,
                node_compact_filters=self.node_compact_filters,
                node_network_limited=self.node_network_limited,
            )
            if await v1_peer.connect(start_height, retry=retry):
                return v1_peer
        return None

    async def connect_to_peers(self, start_height: int = 0):
        """Connect to full-relay peers up to max_peers.

        Enforces /16 network group diversification to resist eclipse attacks.
        Each outbound connection must be from a unique network group.

        During the initial call (few peers), limits attempts to avoid
        blocking startup.  maintain_connections() fills remaining slots.
        """
        attempts = 0
        # Limit attempts so we don't block startup.  Stop early once we
        # have 8 peers (Bitcoin Core's default outbound count) — the
        # maintain_connections loop will fill remaining slots in the
        # background without blocking the sync startup.
        min_peers = 8
        max_attempts = min(len(self.known_addrs) + 10, 40)

        while len(self.peers) < self.max_peers and attempts < max_attempts and \
              len(self.peers) < min_peers:
            attempts += 1

            # Use address manager with network group + ASN exclusion for diversity
            exclude = self._all_outbound_addrs() | set(self.inbound_peers.keys())
            addr = self.addrman.select_for_connection(
                exclude=exclude,
                exclude_groups=self._outbound_netgroups,
                exclude_asns=self._outbound_asns,
            )

            # Fall back to known_addrs if addrman is empty
            if not addr:
                available = (
                    self.known_addrs
                    - self._all_outbound_addrs()
                    - {a for a in self.known_addrs if self.ban_manager.is_banned(a)}
                )
                # Filter by network group
                available = {
                    a for a in available
                    if self._netgroup(a.split(":")[0]) not in self._outbound_netgroups
                }
                if not available:
                    break
                addr = random.choice(list(available))

            # Check exponential backoff
            if not self._should_retry(addr):
                continue

            # Try to connect (full-relay: relay_txs=True)
            host, port = addr.split(':')
            port = int(port)

            # Eclipse protection: enforce /16 network group diversity
            group = self._netgroup(host)
            if group in self._outbound_netgroups:
                continue  # skip duplicate network group

            # Determine proxy — .onion peers require a SOCKS5 proxy
            peer_proxy = self._proxy_for_host(host)
            if is_onion_host(host) and not peer_proxy:
                logger.debug(f"Skipping .onion peer {addr}: no proxy configured")
                continue

            peer = await self._dial_outbound(
                host, port,
                relay_txs=True,
                start_height=start_height,
                retry=False,
            )

            if peer is not None:
                self.peers[addr] = peer
                self.retry_counts[addr] = 0  # Reset retry count on success
                self.addrman.mark_good(host, port)
                self._outbound_netgroups.add(group)  # track /16 diversity
                # ASN-diversity tracking (FIX-51)
                if self.addrman.using_asmap():
                    asn = self.addrman.get_mapped_as(host, 1)  # default NET_IPV4
                    if asn > 0:
                        self._outbound_asns.add(asn)
                self._register_compact_handlers(peer, addr)
                self._register_bloom_handlers(peer, addr)
                self._register_addr_handlers(peer, addr)
                asyncio.ensure_future(self.negotiate_compact_blocks(peer))
                # Request addresses from new outbound peers
                asyncio.ensure_future(self._send_getaddr(peer))
                # Negotiate Erlay reconciliation for full-relay peers
                if self.erlay_enabled:
                    self._register_erlay_handlers(peer, addr)
                    asyncio.ensure_future(self._negotiate_erlay(peer, addr))
                # Negotiate BIP 331 package relay for full-relay peers
                if self.package_relay_enabled:
                    self._register_package_relay_handlers(peer, addr)
                    asyncio.ensure_future(self._negotiate_package_relay(peer))
                # Fire outbound-peer hook so the node attaches tx /
                # getdata / getheaders serving handlers to this peer.
                asyncio.ensure_future(self._fire_outbound_peer_callback(peer))
                # Initialize trickle queue for outbound peer (2s avg delay)
                self._trickle_queues[addr] = TrickleQueue(
                    is_inbound=False, wtxid_relay=peer.wtxid_relay
                )
                logger.info(
                    f"Connected to full-relay peer {addr} "
                    f"({len(self.peers)}/{self.max_peers}, group={group})"
                )
            else:
                # Failed to connect
                self.retry_counts[addr] += 1
                self.last_retry_time[addr] = time.time()
                self.addrman.mark_attempt(host, port)

                # Remove from known if too many failures
                if self.retry_counts[addr] >= 3:
                    self.known_addrs.discard(addr)
                    logger.debug(f"Removed {addr} from known addresses after {self.retry_counts[addr]} failures")

    async def connect_to_node(self, host: str, port: int) -> bool:
        """Connect to a specific peer by host and port (for addnode RPC).

        Returns True on success, False on failure.
        """
        addr = f"{host}:{port}"
        if addr in self.peers or addr in self.block_relay_peers:
            logger.info(f"Already connected to {addr}")
            return True
        if self.ban_manager.is_banned(addr) or self.ban_manager.is_banned(host):
            logger.warning(f"Cannot connect to banned peer {addr}")
            return False

        peer = await self._dial_outbound(
            host, port,
            relay_txs=True,
            start_height=self._start_height,
            retry=False,
        )

        if peer is not None:
            # W99 G2: mark as manual so _on_peer_banned skips it.
            peer.is_manual = True
            self.peers[addr] = peer
            self.retry_counts[addr] = 0
            self.addrman.mark_good(host, port)
            group = self._netgroup(host)
            self._outbound_netgroups.add(group)
            self._register_compact_handlers(peer, addr)
            self._register_bloom_handlers(peer, addr)
            self._register_addr_handlers(peer, addr)
            asyncio.ensure_future(self.negotiate_compact_blocks(peer))
            asyncio.ensure_future(self._send_getaddr(peer))
            if self.erlay_enabled:
                self._register_erlay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_erlay(peer, addr))
            if self.package_relay_enabled:
                self._register_package_relay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_package_relay(peer))
            # Fire outbound-peer hook for handler attachment.
            asyncio.ensure_future(self._fire_outbound_peer_callback(peer))
            self._trickle_queues[addr] = TrickleQueue(
                is_inbound=False, wtxid_relay=peer.wtxid_relay
            )
            logger.info(f"Connected to manually added peer {addr}")
            return True
        else:
            self.addrman.mark_attempt(host, port)
            logger.warning(f"Failed to connect to {addr}")
            return False

    async def _connect_block_relay_peers(self, start_height: int = 0):
        """Connect block-relay-only outbound peers up to max_block_relay_only.

        Enforces /16 network group diversification for eclipse resistance.
        """
        attempts = 0
        max_attempts = len(self.known_addrs) + 100

        while len(self.block_relay_peers) < self.max_block_relay_only and attempts < max_attempts:
            attempts += 1

            # Use address manager with network group + ASN exclusion
            exclude = self._all_outbound_addrs() | set(self.inbound_peers.keys())
            addr = self.addrman.select_for_connection(
                exclude=exclude,
                exclude_groups=self._outbound_netgroups,
                exclude_asns=self._outbound_asns,
            )

            # Fall back to known_addrs
            if not addr:
                available = (
                    self.known_addrs
                    - self._all_outbound_addrs()
                    - {a for a in self.known_addrs if self.ban_manager.is_banned(a)}
                )
                available = {
                    a for a in available
                    if self._netgroup(a.split(":")[0]) not in self._outbound_netgroups
                }
                if not available:
                    break
                addr = random.choice(list(available))

            if not self._should_retry(addr):
                continue

            host, port = addr.split(':')
            port = int(port)

            # Eclipse protection: enforce network group diversity
            group = self._netgroup(host)
            if group in self._outbound_netgroups:
                continue

            # Determine proxy — .onion peers require a SOCKS5 proxy
            peer_proxy = self._proxy_for_host(host)
            if is_onion_host(host) and not peer_proxy:
                logger.debug(f"Skipping .onion block-relay peer {addr}: no proxy configured")
                continue

            peer = await self._dial_outbound(
                host, port,
                relay_txs=False,
                start_height=start_height,
                retry=False,
            )

            if peer is not None:
                self.block_relay_peers[addr] = peer
                self.retry_counts[addr] = 0
                self.addrman.mark_good(host, port)
                self._outbound_netgroups.add(group)  # track /16 diversity
                # ASN-diversity tracking (FIX-51)
                if self.addrman.using_asmap():
                    asn = self.addrman.get_mapped_as(host, 1)  # default NET_IPV4
                    if asn > 0:
                        self._outbound_asns.add(asn)
                # Register only the compact-block *receive* handlers (for
                # unsolicited cmpctblock messages) but do NOT send sendcmpct
                # and do NOT register addr handlers or request addresses.
                self._register_compact_handlers(peer, addr)
                self._register_bloom_handlers(peer, addr)
                # Explicitly skip: negotiate_compact_blocks, _register_addr_handlers, _send_getaddr
                # Block-relay-only peers still benefit from the outbound
                # callback so that getheaders/getdata for blocks works.
                asyncio.ensure_future(self._fire_outbound_peer_callback(peer))
                logger.info(
                    f"Connected to block-relay-only peer {addr} "
                    f"({len(self.block_relay_peers)}/{self.max_block_relay_only}, group={group})"
                )
            else:
                self.retry_counts[addr] += 1
                self.last_retry_time[addr] = time.time()
                self.addrman.mark_attempt(host, port)
                if self.retry_counts[addr] >= 3:
                    self.known_addrs.discard(addr)
                    logger.debug(
                        f"Removed {addr} from known addresses after "
                        f"{self.retry_counts[addr]} failures"
                    )

    def _should_retry(self, addr: str) -> bool:
        retry_count = self.retry_counts.get(addr, 0)
        if retry_count == 0:
            return True

        last_retry = self.last_retry_time.get(addr, 0)
        elapsed = time.time() - last_retry

        # Exponential backoff: 2^retry_count seconds
        backoff_time = min(2 ** retry_count, 300)  # Max 5 minutes

        return elapsed >= backoff_time

    async def maintain_connections(self, start_height: int):
        """Maintain peer connections and eclipse protections."""
        while self.running:
            try:
                # Remove disconnected full-relay outbound peers
                disconnected = [
                    a for a, p in list(self.peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected:
                    peer = self.peers.pop(addr)
                    self._trickle_queues.pop(addr, None)  # cleanup trickle queue
                    # Update outbound netgroups tracking
                    group = self._netgroup(peer.host)
                    self._update_outbound_netgroups()
                    logger.info(f"Removed disconnected full-relay peer {addr}")

                # Remove disconnected block-relay-only outbound peers
                disconnected_bro = [
                    a for a, p in list(self.block_relay_peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected_bro:
                    peer = self.block_relay_peers.pop(addr)
                    # Update outbound netgroups tracking
                    self._update_outbound_netgroups()
                    logger.info(f"Removed disconnected block-relay-only peer {addr}")

                # Remove disconnected inbound peers
                disconnected_in = [
                    a for a, p in list(self.inbound_peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected_in:
                    peer = self.inbound_peers.pop(addr)
                    self._trickle_queues.pop(addr, None)  # cleanup trickle queue
                    # Update inbound netgroups tracking
                    group = self._netgroup(peer.host)
                    if group in self._inbound_netgroups:
                        self._inbound_netgroups[group] -= 1
                        if self._inbound_netgroups[group] <= 0:
                            del self._inbound_netgroups[group]
                    logger.info(f"Removed disconnected inbound peer {addr}")

                # Re-seed from DNS when we have no peers and no known
                # addresses — mirrors Bitcoin Core's ThreadDNSAddressSeed
                # which re-queries seeds when the address manager is empty.
                total_outbound = len(self.peers) + len(self.block_relay_peers)
                if total_outbound == 0 and not self.known_addrs:
                    logger.info(
                        "No connected peers and address pool is empty, "
                        "re-seeding from DNS..."
                    )
                    await self.discover_peers()

                # Reconnect to --connect peers that have dropped
                for host, port in self._connect_addrs:
                    addr = f"{host}:{port}"
                    if addr not in self.peers and addr not in self.block_relay_peers:
                        # --connect peers are always allowed; unban if needed
                        if self.ban_manager.is_banned(addr):
                            self.ban_manager.unban(addr)
                        if self.ban_manager.is_banned(host):
                            self.ban_manager.unban(host)
                        try:
                            logger.info(f"Reconnecting to --connect peer {addr}")
                            await self.connect_to_node(host, port)
                        except Exception as e:
                            logger.warning(f"Failed to reconnect to {addr}: {e}")

                # Refill full-relay outbound slots
                if len(self.peers) < self.max_peers:
                    await self.connect_to_peers(start_height)

                # Refill block-relay-only outbound slots
                if len(self.block_relay_peers) < self.max_block_relay_only:
                    await self._connect_block_relay_peers(start_height)

                # Health check all peers (outbound + block-relay-only + inbound)
                all_peers = (
                    list(self.peers.values())
                    + list(self.block_relay_peers.values())
                    + list(self.inbound_peers.values())
                )
                for peer in all_peers:
                    if not peer.is_connected():
                        continue
                    if peer.latency > 5.0:
                        peer.adjust_score(-1)
                    elif peer.latency > 0 and peer.latency < 0.5:
                        peer.adjust_score(1)

                # Update feefilter for full-relay peers only (skip block-relay-only)
                await self._broadcast_feefilter()

                # Wait before next maintenance
                await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in maintain_connections: {e}")
                await asyncio.sleep(30)

    # BIP 133 Fee Filter

    def _init_feefilter_rounder(self) -> None:
        """Initialize the fee filter rounder (lazy initialization)."""
        if not hasattr(self, '_fee_filter_rounder'):
            self._fee_filter_rounder = FeeFilterRounder()

    def _get_current_feefilter(self) -> int:
        """Get the current fee filter rate from the mempool.

        Returns the minimum fee rate for transaction relay in sat/kvB.
        During IBD or if mempool is unavailable, returns MAX_MONEY to
        suppress all transaction announcements.
        """
        MAX_MONEY = 21_000_000 * 100_000_000  # 21 million BTC in satoshis

        if self._mempool is None:
            return MIN_RELAY_FEE_RATE

        # Check if we're in initial block download (IBD)
        # During IBD, set filter to MAX_MONEY to suppress tx announcements
        if hasattr(self, '_in_ibd') and self._in_ibd:
            return MAX_MONEY

        try:
            # Use get_mempool_info() which returns min_fee_rate in sat/vB
            info = self._mempool.get_mempool_info()
            min_rate_satvb = info.get("min_fee_rate", 0)
            # Convert sat/vB to sat/kvB
            return max(int(min_rate_satvb * 1000), MIN_RELAY_FEE_RATE)
        except Exception:
            return MIN_RELAY_FEE_RATE

    async def _broadcast_feefilter(self) -> None:
        """Send feefilter messages to peers with hysteresis.

        Implements BIP 133 with Bitcoin Core's timing and privacy behavior:
        - Exponentially distributed broadcast intervals (~10 min average)
        - Hysteresis: only expedite update if fee changed significantly
          (dropped below 75% or rose above 133% of last sent)
        - Random noise via FeeFilterRounder to prevent fingerprinting
        """
        self._init_feefilter_rounder()

        current_filter = self._get_current_feefilter()
        current_time = time.time()


        for p in self.get_all_ready_peers():
            # Skip block-relay-only peers (they don't relay transactions)
            if not p.relay_txs:
                continue

            await self._maybe_send_feefilter(p, current_filter, current_time)

    async def _maybe_send_feefilter(
        self,
        peer: Peer,
        current_filter: int,
        current_time: float,
    ) -> None:
        """Send feefilter to a peer if conditions are met.

        Implements Bitcoin Core's MaybeSendFeefilter() logic:
        1. If scheduled time has passed, round and send if changed
        2. If fee changed significantly (3/4 to 4/3) and >5min until
           next scheduled send, expedite to within 5 minutes

        Args:
            peer: The peer to potentially send feefilter to
            current_filter: Current mempool minimum fee in sat/kvB
            current_time: Current timestamp
        """
        from ouroboros.p2p_messages import FeeFilterMessage

        # Check if it's time for scheduled broadcast
        if current_time > peer.next_feefilter_time:
            # Round with noise for privacy
            filter_to_send = self._fee_filter_rounder.round(current_filter)
            # Ensure minimum relay fee floor
            filter_to_send = max(filter_to_send, MIN_RELAY_FEE_RATE)

            # Only send if value changed
            if filter_to_send != peer.feefilter_sent:
                try:
                    msg = FeeFilterMessage(feerate=filter_to_send).to_network_message(
                        self.network
                    )
                    await peer.send_message(msg)
                    peer.feefilter_sent = filter_to_send
                    logger.debug(
                        f"Sent feefilter {filter_to_send} sat/kvB to "
                        f"{peer.host}:{peer.port}"
                    )
                except Exception as e:
                    logger.debug(f"Failed to send feefilter to {peer.host}:{peer.port}: {e}")

            # Schedule next broadcast with exponential distribution
            # Average interval is AVG_FEEFILTER_BROADCAST_INTERVAL (10 min)
            delay = random.expovariate(1.0 / AVG_FEEFILTER_BROADCAST_INTERVAL)
            peer.next_feefilter_time = current_time + delay

        # Check hysteresis: if fee changed substantially and next broadcast
        # is more than MAX_FEEFILTER_CHANGE_DELAY away, expedite it
        elif (
            current_time + MAX_FEEFILTER_CHANGE_DELAY < peer.next_feefilter_time
            and peer.feefilter_sent > 0
        ):
            # Hysteresis thresholds: 3/4 (75%) and 4/3 (133%)
            # current_filter < 3/4 * sent  OR  current_filter > 4/3 * sent
            if (
                current_filter < (3 * peer.feefilter_sent) // 4
                or current_filter > (4 * peer.feefilter_sent) // 3
            ):
                # Expedite: schedule within MAX_FEEFILTER_CHANGE_DELAY
                peer.next_feefilter_time = current_time + random.uniform(
                    0, MAX_FEEFILTER_CHANGE_DELAY
                )
                logger.debug(
                    f"Expedited feefilter for {peer.host}:{peer.port} "
                    f"(current={current_filter}, sent={peer.feefilter_sent})"
                )

    def set_ibd_state(self, in_ibd: bool) -> None:
        """Set the initial block download state.

        During IBD, feefilter is set to MAX_MONEY to suppress all
        transaction relay.

        Args:
            in_ibd: True if currently in initial block download
        """
        self._in_ibd = in_ibd

    # BIP 152 Compact Blocks #

    def set_mempool(self, mempool) -> None:
        """Provide the mempool for compact block reconstruction."""
        self._mempool = mempool

    def set_database(self, database) -> None:
        """Provide the database for block lookups (getblocktxn responses)."""
        self._database = database

    def set_compact_block_handler(self, handler) -> None:
        """Register a callback for fully-reconstructed compact blocks.

        handler(block_hash: bytes, header: bytes, txs: List[Transaction]) -> None

        ``header`` is the 80-byte block header from the cmpctblock message.
        ``txs`` is the complete ordered transaction list.

        Called once the full transaction list is assembled — either
        immediately when all short IDs matched the mempool, or after the
        getblocktxn/blocktxn round-trip fills in the missing slots.
        The handler should serialize header+txs into wire format and submit
        the resulting bytes to the block sync pipeline.
        """
        self._on_compact_block = handler

    async def negotiate_compact_blocks(self, peer: Peer) -> None:
        """Send ``sendcmpct`` to a newly-connected peer."""
        msg = SendCmpctMessage(announce=False, version=self.compact_block_version)
        try:
            await peer.send_message(msg.to_network_message(self.network))
            logger.debug(f"Sent sendcmpct (v{self.compact_block_version}) to "
                         f"{peer.host}:{peer.port}")
        except Exception as e:
            logger.warning(f"Failed to send sendcmpct to {peer.host}:{peer.port}: {e}")

    def _register_compact_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up compact-block message handlers on a peer."""
        async def on_sendcmpct(msg: NetworkMessage):
            sc = SendCmpctMessage.from_payload(msg.payload)
            # Bitcoin Core net_processing.cpp line 3907:
            #   if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
            # Only version 2 (witness-based) is supported.  Ignore v1 entirely.
            from ouroboros.compact_blocks import CMPCTBLOCKS_VERSION
            if sc.version != CMPCTBLOCKS_VERSION:
                logger.debug(
                    f"Peer {addr} sent sendcmpct with unsupported version "
                    f"{sc.version} (expected {CMPCTBLOCKS_VERSION}); ignoring"
                )
                return
            self.cmpct_peers.add(addr)
            if sc.announce:
                peer.wants_cmpctblock = True
            logger.info(f"Peer {addr} supports compact blocks v{sc.version}"
                        f"{' (announce)' if sc.announce else ''}")

        async def on_cmpctblock(msg: NetworkMessage):
            from ouroboros.compact_blocks import (
                MAX_CMPCTBLOCK_DEPTH,
                CompactBlock,
                ReadStatus,
            )
            try:
                cb = CompactBlock.deserialize(msg.payload)
            except (ValueError, Exception) as exc:
                logger.warning(f"Malformed cmpctblock from {addr}: {exc}")
                return

            # Bitcoin Core net_processing.cpp line 4576 depth gate:
            #   if (pindex->nHeight <= m_chainman.ActiveChain().Height() + 2)
            # Only process compact blocks that are within MAX_CMPCTBLOCK_DEPTH
            # of our tip.  We look up the prev-block in our chain to derive
            # the announced height; fall through (best-effort) if unknown.
            if self._database is not None:
                try:
                    _, our_height = self._database.get_best_block()
                    # prev-block hash is at bytes [4:36] of an 80-byte header
                    prev_hash = cb.header[4:36]
                    prev_block = self._database.get_block(prev_hash)
                    if prev_block is not None:
                        prev_height = getattr(prev_block, 'height', None)
                        if prev_height is not None:
                            announced_height = prev_height + 1
                            if announced_height < our_height - MAX_CMPCTBLOCK_DEPTH:
                                logger.debug(
                                    f"Ignoring cmpctblock from {addr}: "
                                    f"height {announced_height} is more than "
                                    f"{MAX_CMPCTBLOCK_DEPTH} below our tip "
                                    f"{our_height}"
                                )
                                return
                except Exception:
                    pass  # height check is best-effort; proceed if unavailable

            # Validate structure before reconstruction (InitData gates)
            status = cb.validate()
            if status == ReadStatus.INVALID:
                logger.warning(
                    f"Invalid cmpctblock structure from {addr} "
                    f"(READ_STATUS_INVALID); ignoring"
                )
                return
            if status == ReadStatus.FAILED:
                logger.debug(
                    f"cmpctblock from {addr} failed structural check "
                    f"(short-ID collision / bucket overflow); ignoring"
                )
                return

            if self._mempool is not None:
                partial_txs, missing = cb.reconstruct_partial(self._mempool)
            else:
                # No mempool — all txs are missing; allocate empty slots
                total = len(cb.short_ids) + len(cb.prefilled_txs)
                partial_txs = [None] * total
                # Pre-fill any prefilled txs even without a mempool
                for pf in cb.prefilled_txs:
                    partial_txs[pf.index] = pf.tx
                missing = [i for i in range(total) if partial_txs[i] is None]

            if not missing:
                # All txs resolved immediately — fire the handler now.
                if self._on_compact_block:
                    self._on_compact_block(cb.block_hash, cb.header, partial_txs)
            else:
                # Store partial state for the getblocktxn round-trip.
                # Keyed by block_hash; on_blocktxn will merge + fire handler.
                # BUG-2 fix: mirrors Core's PartiallyDownloadedBlock (blockencodings.h)
                self._partial_cmpct_blocks[cb.block_hash] = (cb, partial_txs)
                from ouroboros.compact_blocks import BlockTransactionsRequest
                req = BlockTransactionsRequest(
                    block_hash=cb.block_hash, indices=missing)
                gbt = GetBlockTxnMessage(payload_bytes=req.serialize())
                try:
                    await peer.send_message(
                        gbt.to_network_message(self.network))
                except Exception as e:
                    logger.warning(f"Failed to send getblocktxn to {addr}: {e}")

        async def on_blocktxn(msg: NetworkMessage):
            from ouroboros.compact_blocks import BlockTransactions
            try:
                bt = BlockTransactions.deserialize(msg.payload)
            except (ValueError, Exception) as exc:
                logger.warning(f"Malformed blocktxn from {addr}: {exc}")
                return

            # Look up the in-flight partial block stored by on_cmpctblock.
            partial_entry = self._partial_cmpct_blocks.pop(bt.block_hash, None)
            if partial_entry is None:
                logger.debug(
                    f"blocktxn from {addr}: no matching in-flight cmpctblock "
                    f"for {bt.block_hash.hex()[:16]}...; ignoring"
                )
                return

            _cb, partial_txs = partial_entry

            # Merge: fill None slots (in ascending index order) with the
            # transactions from the blocktxn response.  Bitcoin Core
            # PartiallyDownloadedBlock::FillBlock works the same way —
            # missing indices were sent in order, so responses arrive
            # in the same order.
            received_iter = iter(bt.transactions)
            try:
                for i, tx in enumerate(partial_txs):
                    if tx is None:
                        partial_txs[i] = next(received_iter)
            except StopIteration:
                logger.warning(
                    f"blocktxn from {addr}: fewer txs than expected for "
                    f"{bt.block_hash.hex()[:16]}...; falling back to getdata"
                )
                # Fall back: request the full block via getdata
                try:
                    from ouroboros.p2p_messages import INV_TYPE_BLOCK, GetDataMessage
                    getdata = GetDataMessage(inventory=[(INV_TYPE_BLOCK, bt.block_hash)])
                    await peer.send_message(getdata.to_network_message(self.network))
                except Exception as e:
                    logger.warning(f"Failed to send getdata fallback: {e}")
                return

            # Verify all slots are filled
            if any(tx is None for tx in partial_txs):
                logger.warning(
                    f"blocktxn from {addr}: unfilled tx slots after merge for "
                    f"{bt.block_hash.hex()[:16]}...; falling back to getdata"
                )
                try:
                    from ouroboros.p2p_messages import INV_TYPE_BLOCK, GetDataMessage
                    getdata = GetDataMessage(inventory=[(INV_TYPE_BLOCK, bt.block_hash)])
                    await peer.send_message(getdata.to_network_message(self.network))
                except Exception as e:
                    logger.warning(f"Failed to send getdata fallback: {e}")
                return

            # All txs assembled — fire the registered block handler.
            if self._on_compact_block:
                self._on_compact_block(bt.block_hash, _cb.header, partial_txs)

        async def on_getblocktxn(msg: NetworkMessage):
            """Handle getblocktxn: respond with requested transactions.

            Bitcoin Core net_processing.cpp lines 4245-4303:
            - Silently ignore requests for blocks we don't have.
            - Only serve blocks within MAX_BLOCKTXN_DEPTH (10) of tip;
              for older blocks send a full block (MSG_WITNESS_BLOCK) instead.
            - Misbehave on out-of-bounds tx indices.
            """
            from ouroboros.compact_blocks import (
                MAX_BLOCKTXN_DEPTH,
                BlockTransactions,
                BlockTransactionsRequest,
            )
            try:
                req = BlockTransactionsRequest.deserialize(msg.payload)
                logger.debug(
                    f"Received getblocktxn from {addr}: "
                    f"{req.block_hash.hex()} ({len(req.indices)} indices)")
                # Look up the full block in our database
                if self._database is not None:
                    block = self._database.get_block(req.block_hash)
                    if block is None:
                        logger.debug(
                            f"getblocktxn: block not found "
                            f"{req.block_hash.hex()}")
                        return

                    # Bitcoin Core net_processing.cpp line 4276:
                    #   if (pindex->nHeight >= tip_height - MAX_BLOCKTXN_DEPTH)
                    # Only serve requests within MAX_BLOCKTXN_DEPTH of tip.
                    try:
                        _, tip_height = self._database.get_best_block()
                        block_height = getattr(block, 'height', None)
                        if block_height is not None and tip_height is not None:
                            if block_height < tip_height - MAX_BLOCKTXN_DEPTH:
                                logger.debug(
                                    f"getblocktxn: block {req.block_hash.hex()} "
                                    f"at height {block_height} is > "
                                    f"{MAX_BLOCKTXN_DEPTH} below tip "
                                    f"{tip_height}; not serving"
                                )
                                return
                    except Exception:
                        pass  # depth check is best-effort

                    txs = block.transactions
                    requested_txs = []
                    out_of_bounds = False
                    for idx in req.indices:
                        if idx >= len(txs):
                            # Bitcoin Core SendBlockTransactions:
                            #   Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")
                            logger.warning(
                                f"getblocktxn from {addr}: out-of-bounds "
                                f"index {idx} (block has {len(txs)} txs); "
                                "dropping response"
                            )
                            out_of_bounds = True
                            break
                        requested_txs.append(txs[idx])
                    if out_of_bounds:
                        return

                    bt_resp = BlockTransactions(
                        block_hash=req.block_hash,
                        transactions=requested_txs)
                    bt_msg = BlockTxnMessage(
                        payload_bytes=bt_resp.serialize())
                    await peer.send_message(
                        bt_msg.to_network_message(self.network))
            except Exception as e:
                logger.warning(f"Error handling getblocktxn from {addr}: {e}")

        async def on_sendheaders(msg: NetworkMessage):
            peer.wants_headers = True
            logger.debug(f"Peer {addr} wants headers announcements")

        async def on_feefilter(msg: NetworkMessage):
            from ouroboros.p2p_messages import FeeFilterMessage
            ff = FeeFilterMessage.from_payload(msg.payload)
            peer.peer_feefilter = ff.feerate
            logger.debug(f"Peer {addr} feefilter: {ff.feerate} sat/kB")

        async def on_wtxidrelay(msg: NetworkMessage):
            logger.debug(f"Peer {addr} supports wtxid relay")

        async def on_sendaddrv2(msg: NetworkMessage):
            logger.debug(f"Peer {addr} supports addrv2")

        async def on_notfound(msg: NetworkMessage):
            from ouroboros.p2p_messages import NotFoundMessage
            nf = NotFoundMessage.from_payload(msg.payload)
            logger.debug(f"Peer {addr} notfound: {len(nf.inventory)} items")

        async def on_mempool(msg: NetworkMessage):
            # BIP-35: gate the MEMPOOL handler on whether *we* advertised
            # NODE_BLOOM in our version message. This mirrors Bitcoin
            # Core net_processing.cpp ~4855:
            #     if (!(peer.m_our_services & NODE_BLOOM) &&
            #         !pfrom.HasPermission(NetPermissionFlags::Mempool))
            # The BIP-37 fRelay (peer.relay_txs) check is independent —
            # it gates outbound tx-INV relay, not mempool dump requests.
            from ouroboros.p2p_messages import (
                INV_TYPE_TX,
                MSG_WTX,
                NODE_BLOOM,
                NODE_WITNESS,
                InvMessage,
            )
            if not (peer.our_services & NODE_BLOOM):
                logger.debug(
                    f"Ignoring mempool request from {addr}: "
                    "NODE_BLOOM not advertised"
                )
                return
            if self._mempool is None:
                return
            all_txids = list(self._mempool.transactions.keys())
            if not all_txids:
                return
            # Use wtxid (MSG_WTX) inv type for peers that advertised
            # NODE_WITNESS; otherwise fall back to MSG_TX (legacy txid).
            # Chunk at MAX_INV_SZ = 50_000 (Bitcoin Core protocol.h).
            MAX_INV_SZ = 50000
            inv_type = MSG_WTX if (peer.services & NODE_WITNESS) else INV_TYPE_TX
            for chunk_start in range(0, len(all_txids), MAX_INV_SZ):
                chunk = all_txids[chunk_start:chunk_start + MAX_INV_SZ]
                inv = InvMessage([(inv_type, txid) for txid in chunk])
                try:
                    await peer.send_message(inv.to_network_message(self.network))
                except Exception as e:
                    logger.warning(f"Failed to send mempool inv to {addr}: {e}")
                    return

        peer.register_handler("sendcmpct", on_sendcmpct)
        peer.register_handler("cmpctblock", on_cmpctblock)
        peer.register_handler("blocktxn", on_blocktxn)
        peer.register_handler("getblocktxn", on_getblocktxn)
        peer.register_handler("sendheaders", on_sendheaders)
        peer.register_handler("feefilter", on_feefilter)
        peer.register_handler("wtxidrelay", on_wtxidrelay)
        peer.register_handler("sendaddrv2", on_sendaddrv2)
        peer.register_handler("notfound", on_notfound)
        peer.register_handler("mempool", on_mempool)

    # BIP-111 bloom filter disconnect handlers

    def _register_bloom_handlers(self, peer: Peer, addr: str) -> None:
        """Register BIP-111 disconnect handlers for bloom filter messages.

        Per BIP-111 and bitcoin-core/src/net_processing.cpp:4964-4990, when a
        peer sends filterload, filteradd, or filterclear and we have NOT
        advertised NODE_BLOOM, we MUST disconnect the peer.  We never
        advertise NODE_BLOOM unless peer_bloom_filters=True (config default:
        False) because we have no CBloomFilter implementation — advertising it
        would be a protocol violation.

        merkleblock is server→client (unusual as an inbound message); we log
        and drop it without disconnecting, matching Core's ignore path for
        unexpected server-side messages.
        """
        from ouroboros.p2p_messages import NODE_BLOOM

        async def on_filterload(msg: NetworkMessage):
            # BIP-111 / Core net_processing.cpp:4965:
            #   if (!(peer.m_our_services & NODE_BLOOM)) { pfrom.fDisconnect = true; return; }
            if not (peer.our_services & NODE_BLOOM):
                logger.warning(
                    f"BIP-111: disconnecting {addr} — sent filterload but "
                    "NODE_BLOOM not advertised"
                )
                asyncio.ensure_future(peer.disconnect())
                return
            # NODE_BLOOM is advertised (peer_bloom_filters=True in config) but
            # we have no CBloomFilter implementation.  Log and drop rather
            # than crashing; this path is unreachable with the default config.
            logger.warning(
                f"filterload from {addr}: BIP-37 not implemented; "
                "disconnecting (no CBloomFilter)"
            )
            asyncio.ensure_future(peer.disconnect())

        async def on_filteradd(msg: NetworkMessage):
            # BIP-111 / Core net_processing.cpp:4988-4990: same NODE_BLOOM gate.
            if not (peer.our_services & NODE_BLOOM):
                logger.warning(
                    f"BIP-111: disconnecting {addr} — sent filteradd but "
                    "NODE_BLOOM not advertised"
                )
                asyncio.ensure_future(peer.disconnect())
                return
            logger.warning(
                f"filteradd from {addr}: BIP-37 not implemented; "
                "disconnecting (no CBloomFilter)"
            )
            asyncio.ensure_future(peer.disconnect())

        async def on_filterclear(msg: NetworkMessage):
            # BIP-111 / Core net_processing.cpp:5016-5018: same NODE_BLOOM gate.
            if not (peer.our_services & NODE_BLOOM):
                logger.warning(
                    f"BIP-111: disconnecting {addr} — sent filterclear but "
                    "NODE_BLOOM not advertised"
                )
                asyncio.ensure_future(peer.disconnect())
                return
            logger.warning(
                f"filterclear from {addr}: BIP-37 not implemented; "
                "disconnecting (no CBloomFilter)"
            )
            asyncio.ensure_future(peer.disconnect())

        async def on_merkleblock(msg: NetworkMessage):
            # merkleblock is an outbound server→client message; receiving it
            # inbound is unusual (e.g. a misbehaving peer or test harness).
            # Core ignores it silently; we log at debug and drop.
            logger.debug(
                f"Received unexpected merkleblock from {addr}; dropping "
                "(merkleblock is a server→client message)"
            )

        peer.register_handler("filterload", on_filterload)
        peer.register_handler("filteradd", on_filteradd)
        peer.register_handler("filterclear", on_filterclear)
        peer.register_handler("merkleblock", on_merkleblock)

    # Address gossip (addr / addrv2 / getaddr)

    def _register_addr_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up addr/addrv2/getaddr handlers on a peer."""

        async def on_addr(msg: NetworkMessage):
            try:
                am = AddrMessage.from_payload(msg.payload)
                if not self._rate_limit_addr_relay(addr, len(am.addresses)):
                    return
                added = 0
                for ts, net_addr in am.addresses:
                    host_str = self._netaddr_to_host(net_addr)
                    if host_str and not self.ban_manager.is_banned(host_str):
                        if self.addrman.add(
                            host_str, net_addr.port,
                            services=net_addr.services,
                            timestamp=float(ts),
                            source=addr,
                        ):
                            added += 1
                        self.known_addrs.add(f"{host_str}:{net_addr.port}")
                if added:
                    logger.debug(f"Learned {added} new addresses from {addr}")
                    # Relay to 1-2 random peers
                    self._relay_addr(msg, exclude=addr)
            except Exception as e:
                logger.debug(f"Error parsing addr from {addr}: {e}")

        async def on_addrv2(msg: NetworkMessage):
            try:
                am = AddrV2Message.from_payload(msg.payload)
                if not self._rate_limit_addr_relay(addr, len(am.addresses)):
                    return
                added = 0
                for entry in am.addresses:
                    # AddrV2Entry is a @dataclass — use attribute access, not
                    # dict-style .get().  Prior to W117 FIX-57 this was
                    # entry.get("network_id", 0) which raised AttributeError
                    # and was silently swallowed by the broad ``except`` below,
                    # making every received addrv2 entry a no-op.
                    net_id = entry.network_id
                    if net_id not in (1, 2, 4):
                        continue  # skip I2P/CJDNS for now (1=IPv4, 2=IPv6, 4=Tor v3)
                    addr_bytes = entry.addr
                    port = entry.port
                    services = entry.services
                    ts = entry.time
                    host_str = self._addr_bytes_to_host(net_id, addr_bytes)
                    if host_str and not self.ban_manager.is_banned(host_str):
                        if self.addrman.add(
                            host_str, port,
                            services=services,
                            timestamp=float(ts),
                            source=addr,
                        ):
                            added += 1
                        self.known_addrs.add(f"{host_str}:{port}")
                if added:
                    logger.debug(f"Learned {added} new addresses (v2) from {addr}")
                    self._relay_addr(msg, exclude=addr)
            except (ValueError, struct.error) as e:
                # Expected for malformed wire payloads (truncated, bad varint,
                # oversize address).  ``AddrV2Message.from_payload`` raises
                # ValueError; varint/struct unpacking can raise struct.error.
                logger.debug(f"Error parsing addrv2 from {addr}: {e}")
            except (AttributeError, KeyError, TypeError) as e:
                # Programming-error class: must NOT be silently swallowed at
                # debug level.  W117 BUG-1 was an AttributeError hidden by the
                # previous broad ``except Exception`` clause.  Re-raising would
                # tear down the peer handler; logging at error keeps the node
                # alive but ensures these surface in production logs.
                logger.error(
                    f"on_addrv2 internal error from {addr}: {e}", exc_info=True
                )

        async def on_getaddr(msg: NetworkMessage):
            try:
                infos = self.addrman.get_addresses(count=1000)
                if not infos:
                    return
                from ouroboros.p2p_messages import NetworkAddress
                addresses = []
                for info in infos:
                    try:
                        net_addr = NetworkAddress.from_ipv4(
                            info.host, info.port, services=info.services,
                        )
                        addresses.append((int(info.last_seen), net_addr))
                    except (ValueError, AttributeError):
                        continue
                if addresses:
                    resp = AddrMessage(addresses=addresses)
                    await peer.send_message(
                        resp.to_network_message(self.network)
                    )
                    logger.debug(
                        f"Sent {len(addresses)} addresses to {addr}"
                    )
            except Exception as e:
                logger.debug(f"Error handling getaddr from {addr}: {e}")

        peer.register_handler("addr", on_addr)
        peer.register_handler("addrv2", on_addrv2)
        peer.register_handler("getaddr", on_getaddr)

    async def _send_getaddr(self, peer: Peer) -> None:
        try:
            msg = GetAddrMessage().to_network_message(self.network)
            await peer.send_message(msg)
            logger.debug(f"Sent getaddr to {peer.host}:{peer.port}")
        except Exception as e:
            logger.debug(f"Failed to send getaddr to {peer.host}:{peer.port}: {e}")

    def _relay_addr(self, msg: NetworkMessage, exclude: str = "") -> None:
        all_items = list(self.peers.items()) + list(self.inbound_peers.items())
        candidates = [
            p for a, p in all_items
            if a != exclude and p.is_connected() and p.relay_txs
        ]
        targets = random.sample(candidates, min(2, len(candidates)))
        for p in targets:
            try:
                asyncio.ensure_future(p.send_message(msg))
            except Exception:
                pass

    def _rate_limit_addr_relay(self, addr: str, count: int) -> bool:
        now = time.time()
        day_start = self._addr_relay_day.get(addr, 0)
        if now - day_start > 86400:
            self._addr_relay_counts[addr] = 0
            self._addr_relay_day[addr] = now
        self._addr_relay_counts[addr] += count
        return self._addr_relay_counts[addr] <= 1000

    @staticmethod
    def _netaddr_to_host(net_addr) -> str | None:
        ip_bytes = net_addr.ip
        # IPv4-mapped IPv6: ::ffff:a.b.c.d
        if ip_bytes[:12] == b"\x00" * 10 + b"\xff\xff":
            return ".".join(str(b) for b in ip_bytes[12:16])
        # Pure IPv4 (shouldn't happen in protocol, but be safe)
        if len(ip_bytes) == 4:
            return ".".join(str(b) for b in ip_bytes)
        return None

    @staticmethod
    def _addr_bytes_to_host(net_id: int, addr_bytes: bytes) -> str | None:
        """Convert BIP155 address bytes to human-readable host string.

        Supports:
        - net_id=1: IPv4 (4 bytes)
        - net_id=2: IPv6 (16 bytes) - currently skipped
        - net_id=4: Tor v3 (32 bytes ed25519 pubkey)
        - net_id=5: I2P (32 bytes SHA256 hash of destination)
        """
        if net_id == 1 and len(addr_bytes) == 4:
            return ".".join(str(b) for b in addr_bytes)
        if net_id == 2 and len(addr_bytes) == 16:
            # IPv6 — skip for outbound connections for now
            return None
        if net_id == 4 and len(addr_bytes) == 32:
            # Tor v3: 32-byte ed25519 pubkey → base32-encode with checksum
            # Onion v3 address = base32(pubkey || checksum || version)
            # checksum = first 2 bytes of SHA3-256(".onion checksum" || pubkey || version)
            import hashlib as _hl
            version_byte = b"\x03"
            checksum_prefix = b".onion checksum"
            h = _hl.sha3_256(checksum_prefix + addr_bytes + version_byte).digest()
            checksum = h[:2]
            onion_body = addr_bytes + checksum + version_byte
            onion_host = base64.b32encode(onion_body).decode("ascii").lower() + ".onion"
            return onion_host
        if net_id == 5 and len(addr_bytes) == 32:
            # I2P: 32-byte SHA256 hash of destination → base32 .b32.i2p address
            # The address is the base32 encoding of the hash (without padding)
            i2p_host = base64.b32encode(addr_bytes).decode("ascii").lower().rstrip("=") + ".b32.i2p"
            return i2p_host
        return None

    # --- BIP 330 Erlay Reconciliation ---

    async def _negotiate_erlay(self, peer: Peer, addr: str) -> None:
        if not peer.relay_txs:
            # Block-relay-only peers don't participate in tx reconciliation
            return
        try:
            salt = random.getrandbits(64)
            self._erlay_local_salts[addr] = salt
            msg = SendTxRcnclMessage(version=1, salt=salt)
            await peer.send_message(msg.to_network_message(self.network))
            logger.debug(
                f"Sent sendtxrcncl (salt={salt:#018x}) to {addr}"
            )
        except Exception as e:
            logger.warning(f"Failed to send sendtxrcncl to {addr}: {e}")

    def _register_erlay_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up BIP 330 Erlay message handlers on a peer."""

        async def on_sendtxrcncl(msg: NetworkMessage):
            """Handle incoming sendtxrcncl — complete Erlay negotiation."""
            try:
                rcncl = SendTxRcnclMessage.from_payload(msg.payload)
                if rcncl.version < 1:
                    logger.debug(
                        f"Peer {addr} sendtxrcncl version {rcncl.version} "
                        "not supported, ignoring"
                    )
                    return

                our_salt = self._erlay_local_salts.get(addr)
                if our_salt is None:
                    # We haven't sent our sendtxrcncl yet — this is the
                    # peer initiating.  Send ours in reply.
                    our_salt = random.getrandbits(64)
                    self._erlay_local_salts[addr] = our_salt
                    reply = SendTxRcnclMessage(version=1, salt=our_salt)
                    await peer.send_message(
                        reply.to_network_message(self.network)
                    )

                # Erlay is now active on this connection
                recon_set = ReconciliationSet(
                    local_salt=our_salt,
                    remote_salt=rcncl.salt,
                )
                self._erlay_peers[addr] = recon_set
                self._erlay_pending_recon[addr] = False
                logger.info(
                    f"Erlay negotiated with {addr} "
                    f"(version={rcncl.version}, "
                    f"remote_salt={rcncl.salt:#018x})"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling sendtxrcncl from {addr}: {e}"
                )

        async def on_reqtxrcncl(msg: NetworkMessage):
            """Handle incoming reconciliation request — respond with a
            sketch of our local reconciliation set."""
            try:
                req = ReqTxRcnclMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    logger.debug(
                        f"Ignoring reqtxrcncl from non-Erlay peer {addr}"
                    )
                    return

                # Estimate capacity from both sides
                local_size = recon.set_size
                q_frac = req.q / (1 << 15)
                capacity = estimate_sketch_capacity(
                    local_size, req.set_size, q=max(q_frac, 0.1)
                )

                # Build and send our sketch
                sketch = recon.build_sketch(capacity)
                sketch_msg = SketchMessage(sketch_data=sketch.serialize())
                await peer.send_message(
                    sketch_msg.to_network_message(self.network)
                )
                logger.debug(
                    f"Sent sketch (cap={capacity}) to {addr} "
                    f"(local_set={local_size}, remote_set={req.set_size})"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling reqtxrcncl from {addr}: {e}"
                )

        async def on_sketch(msg: NetworkMessage):
            """Handle incoming sketch — decode the difference and send
            reconcildiff with the results."""
            try:
                sketch_msg = SketchMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    logger.debug(
                        f"Ignoring sketch from non-Erlay peer {addr}"
                    )
                    return

                # Determine capacity from sketch size
                capacity = len(sketch_msg.sketch_data) // 4
                if capacity == 0:
                    return

                # Build our local sketch with the same capacity
                local_sketch = recon.build_sketch(capacity)

                # Deserialize the remote sketch
                remote_sketch = Minisketch.deserialize(
                    sketch_msg.sketch_data, capacity
                )

                # Merge (XOR) to get the difference sketch
                diff_sketch = local_sketch.merge(remote_sketch)

                # Decode the symmetric difference
                diff_elements = diff_sketch.decode()

                if diff_elements is None:
                    # Decoding failed — fall back to full INV flood
                    logger.debug(
                        f"Sketch decode failed with {addr}, "
                        "falling back to INV"
                    )
                    diff_msg = ReconcilDiffMessage(
                        success=False, ask_shortids=[]
                    )
                    await peer.send_message(
                        diff_msg.to_network_message(self.network)
                    )
                    # Flood our pending txs via INV as fallback
                    await self._flood_pending_invs(peer, addr)
                    self._erlay_pending_recon[addr] = False
                    return

                # Separate: which elements are ours (peer missing) vs
                # theirs (we're missing)
                local_short_ids = recon.get_short_ids()
                sid_to_txid = recon.short_id_to_txid_map()

                # Elements in diff that we have → peer is missing
                peer_missing_sids = diff_elements & local_short_ids
                # Elements in diff that we don't have → we're missing
                we_missing_sids = diff_elements - local_short_ids

                # Send INVs for txids the peer is missing
                inv_items = []
                for sid in peer_missing_sids:
                    txid = sid_to_txid.get(sid)
                    if txid:
                        inv_items.append((INV_TYPE_TX, txid))
                        recon.mark_announced(txid)

                if inv_items:
                    inv_msg = InvMessage(inv_items)
                    await peer.send_message(
                        inv_msg.to_network_message(self.network)
                    )
                    logger.debug(
                        f"Sent {len(inv_items)} INVs to {addr} "
                        "after reconciliation"
                    )

                # Ask peer for txids we're missing
                diff_msg = ReconcilDiffMessage(
                    success=True,
                    ask_shortids=list(we_missing_sids),
                )
                await peer.send_message(
                    diff_msg.to_network_message(self.network)
                )

                # Clear reconciled transactions
                for sid in peer_missing_sids:
                    txid = sid_to_txid.get(sid)
                    if txid:
                        recon.mark_announced(txid)

                self._erlay_pending_recon[addr] = False
                logger.debug(
                    f"Reconciliation with {addr}: "
                    f"peer_missing={len(peer_missing_sids)}, "
                    f"we_missing={len(we_missing_sids)}, "
                    f"diff_size={len(diff_elements)}"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling sketch from {addr}: {e}"
                )
                self._erlay_pending_recon[addr] = False

        async def on_reconcildiff(msg: NetworkMessage):
            """Handle incoming reconcildiff — the initiator tells us
            what short IDs it wants (txids we have that it lacks)."""
            try:
                diff = ReconcilDiffMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    return

                if not diff.success:
                    # Reconciliation failed on their side — fall back to INV
                    logger.debug(
                        f"Peer {addr} reports reconciliation failure"
                    )
                    await self._flood_pending_invs(peer, addr)
                    return

                # The peer wants us to send INVs for these short IDs
                if diff.ask_shortids:
                    sid_to_txid = recon.short_id_to_txid_map()
                    inv_items = []
                    for sid in diff.ask_shortids:
                        txid = sid_to_txid.get(sid)
                        if txid:
                            inv_items.append((INV_TYPE_TX, txid))
                            recon.mark_announced(txid)
                    if inv_items:
                        inv_msg = InvMessage(inv_items)
                        await peer.send_message(
                            inv_msg.to_network_message(self.network)
                        )
                        logger.debug(
                            f"Sent {len(inv_items)} INVs to {addr} "
                            "in response to reconcildiff"
                        )
            except Exception as e:
                logger.warning(
                    f"Error handling reconcildiff from {addr}: {e}"
                )

        peer.register_handler("sendtxrcncl", on_sendtxrcncl)
        peer.register_handler("reqtxrcncl", on_reqtxrcncl)
        peer.register_handler("sketch", on_sketch)
        peer.register_handler("reconcildiff", on_reconcildiff)

        # If the peer sent sendtxrcncl during the pre-verack window the
        # raw payload was stashed on the Peer; replay it now that the
        # handler is wired (BIP 330 / bitcoin-core net_processing.cpp).
        pending = getattr(peer, "_pending_sendtxrcncl_payload", None)
        if pending is not None:
            peer._pending_sendtxrcncl_payload = None
            replay = NetworkMessage(
                command="sendtxrcncl",
                payload=pending,
                magic=get_magic(self.network),
            )
            asyncio.create_task(on_sendtxrcncl(replay))

    # --- BIP 331 Package Relay ---

    async def _negotiate_package_relay(self, peer: Peer) -> None:
        """Send our ``sendpackages`` to *peer*.

        Bitcoin Core sends sendpackages immediately after verack — we do the
        same.  Block-relay-only peers don't do tx relay so we skip them.
        """
        if not peer.relay_txs:
            return
        try:
            msg = SendPackagesMessage(
                version=self.package_relay_version,
                max_count=self.package_max_count,
                max_weight=self.package_max_weight,
            )
            await peer.send_message(msg.to_network_message(self.network))
            peer._sendpackages_sent = True
            logger.debug(
                f"Sent sendpackages (v{self.package_relay_version}, "
                f"max_count={self.package_max_count}, "
                f"max_weight={self.package_max_weight}) to "
                f"{peer.host}:{peer.port}"
            )
        except Exception as e:
            logger.warning(
                f"Failed to send sendpackages to {peer.host}:{peer.port}: {e}"
            )

    def _register_package_relay_handlers(
        self, peer: Peer, addr: str
    ) -> None:
        """Wire up BIP 331 ``sendpackages`` / ``getpkgtxns`` / ``pkgtxns``
        handlers for *peer*.

        Reference: Bitcoin Core net_processing.cpp ProcessMessage handlers
        for ``sendpackages`` / ``getpkgtxns`` / ``pkgtxns``.
        """

        async def on_sendpackages(msg: NetworkMessage):
            try:
                sp = SendPackagesMessage.from_payload(msg.payload)
            except Exception as e:
                logger.debug(
                    f"Bad sendpackages from {addr}: {e}"
                )
                return
            if sp.version < 1:
                logger.debug(
                    f"Peer {addr} sendpackages version {sp.version} "
                    "not supported, ignoring"
                )
                return
            peer.package_relay_version = sp.version
            peer.package_max_count = sp.max_count
            peer.package_max_weight = sp.max_weight
            peer._sendpackages_received = True
            # Both sides have agreed → mark the connection as package-relay.
            if peer._sendpackages_sent:
                self._package_peers.add(addr)
            logger.info(
                f"Package relay negotiated with {addr} "
                f"(version={sp.version}, max_count={sp.max_count}, "
                f"max_weight={sp.max_weight})"
            )

        async def on_getpkgtxns(msg: NetworkMessage):
            """Respond to a ``getpkgtxns`` request with the matching package.

            The payload is a single 32-byte child wtxid.  Look up the child
            in the mempool, then assemble its ancestor package (parents
            first, child last) and ship it back as ``pkgtxns``.  If we don't
            have the child locally we silently drop the request (Core does
            the same; nothing to send).
            """
            try:
                req = GetPkgTxnsMessage.from_payload(msg.payload)
            except Exception as e:
                logger.debug(f"Bad getpkgtxns from {addr}: {e}")
                return
            if self._mempool is None:
                return
            child = self._mempool.get_transaction_by_wtxid(req.child_wtxid)
            if child is None:
                logger.debug(
                    f"getpkgtxns from {addr}: unknown child wtxid "
                    f"{req.child_wtxid.hex()[:16]}..."
                )
                return

            # Walk ancestors in the mempool to assemble the package in
            # topological order.  Use the per-entry ``parents`` set written
            # by the cluster manager.  Cap the package at our advertised
            # max_count to stay within the negotiated envelope.
            order: list = []
            seen: set[bytes] = set()

            def visit(tx_obj):
                txid = tx_obj.get_txid()
                if txid in seen:
                    return
                seen.add(txid)
                entry = self._mempool.transactions.get(txid)
                if entry is not None:
                    for parent_txid in entry.parents:
                        parent_entry = self._mempool.transactions.get(
                            parent_txid
                        )
                        if parent_entry is not None:
                            visit(parent_entry.tx)
                order.append(tx_obj)

            visit(child)
            if len(order) > self.package_max_count:
                # Drop oldest ancestors so we keep within the limit (child
                # is always the last element).
                order = order[-self.package_max_count:]

            tx_bytes = [tx.serialize_with_witness() for tx in order]
            try:
                resp = PkgTxnsMessage(transactions=tx_bytes)
                await peer.send_message(resp.to_network_message(self.network))
                logger.debug(
                    f"Sent pkgtxns to {addr}: {len(tx_bytes)} txs for "
                    f"child wtxid {req.child_wtxid.hex()[:16]}..."
                )
            except Exception as e:
                logger.warning(f"Failed to send pkgtxns to {addr}: {e}")

        async def on_pkgtxns(msg: NetworkMessage):
            """Accept an inbound package: parse and submit to mempool.

            We only accept packages from peers we negotiated with; Core
            enforces the same gate.  Each transaction is parsed via
            ``TxMessage.from_payload`` (witness-format) then handed to
            ``Mempool.accept_to_memory_pool`` so RBF / fee policy / package
            limits apply.  Failures are logged but not punished.
            """
            if addr not in self._package_peers:
                logger.debug(
                    f"Ignoring pkgtxns from {addr}: package relay "
                    "not negotiated"
                )
                return
            if self._mempool is None:
                return
            try:
                pkg = PkgTxnsMessage.from_payload(msg.payload)
            except Exception as e:
                logger.debug(f"Bad pkgtxns from {addr}: {e}")
                return

            from ouroboros.p2p_messages import TxMessage

            txs = []
            for raw in pkg.transactions:
                try:
                    txs.append(TxMessage.from_payload(raw).transaction)
                except Exception as e:
                    logger.debug(f"Bad tx in pkgtxns from {addr}: {e}")
                    return

            # Submit each tx to the mempool individually; the existing
            # validate_package + add path handles topological order.  A
            # production implementation would call accept_to_memory_pool
            # with package semantics; here we delegate to the mempool's
            # validate_package so the BIP 331 path uses the same code that
            # already exists for local package acceptance.
            try:
                height = self._start_height
                if hasattr(self._mempool, "validate_package"):
                    self._mempool.validate_package(txs, height=height)
                for tx in txs:
                    try:
                        self._mempool.add_transaction(tx, height=height)
                    except Exception as e:
                        logger.debug(
                            f"pkgtxns: failed to add tx from {addr}: {e}"
                        )
            except Exception as e:
                logger.debug(f"Error processing pkgtxns from {addr}: {e}")

        async def on_ancpkginfo(msg: NetworkMessage):
            # ``ancpkginfo`` is only used by the ancestor-package extension
            # of BIP 331; we accept and parse it for forward-compatibility
            # but don't act on it yet.  Logged at DEBUG so it doesn't spam
            # production logs.
            try:
                from ouroboros.p2p_messages import AncPkgInfoMessage
                info = AncPkgInfoMessage.from_payload(msg.payload)
                logger.debug(
                    f"ancpkginfo from {addr}: child={info.child_wtxid.hex()[:16]}..., "
                    f"{len(info.parent_wtxids)} parents"
                )
            except Exception as e:
                logger.debug(f"Bad ancpkginfo from {addr}: {e}")

        peer.register_handler("sendpackages", on_sendpackages)
        peer.register_handler("getpkgtxns", on_getpkgtxns)
        peer.register_handler("pkgtxns", on_pkgtxns)
        peer.register_handler("ancpkginfo", on_ancpkginfo)

    async def _reconciliation_loop(self) -> None:
        """Periodically reconcile transaction sets with Erlay peers."""
        try:
            while self.running:
                await asyncio.sleep(self._reconciliation_interval)
                if not self.running:
                    break

                for addr, recon in list(self._erlay_peers.items()):
                    # Skip peers with no pending transactions
                    if recon.set_size == 0:
                        continue
                    # Skip if reconciliation already in progress
                    if self._erlay_pending_recon.get(addr, False):
                        continue

                    peer = self.get_peer_by_addr(addr)
                    if peer is None or not peer.is_connected():
                        continue

                    try:
                        self._erlay_pending_recon[addr] = True
                        # Send reqtxrcncl to initiate
                        q_coeff = 1  # q = 1/2^15 ≈ minimal estimate
                        req = ReqTxRcnclMessage(
                            set_size=recon.set_size,
                            q=q_coeff,
                        )
                        await peer.send_message(
                            req.to_network_message(self.network)
                        )
                        logger.debug(
                            f"Initiated reconciliation with {addr} "
                            f"(set_size={recon.set_size})"
                        )
                    except Exception as e:
                        self._erlay_pending_recon[addr] = False
                        logger.warning(
                            f"Failed to initiate reconciliation "
                            f"with {addr}: {e}"
                        )
        except asyncio.CancelledError:
            logger.debug("Reconciliation loop cancelled")
        except Exception as e:
            logger.error(f"Error in reconciliation loop: {e}")

    def erlay_add_tx_to_reconcile(self, txid: bytes, exclude_addr: str = "") -> None:
        """
        Queue a transaction for reconciliation with all Erlay peers.

        Instead of immediately broadcasting an INV to every peer, the
        transaction is added to each peer's reconciliation set and will
        be announced during the next reconciliation round.

        For non-Erlay peers, the caller should still send INV directly.

        Args:
            txid: 32-byte transaction hash
            exclude_addr: peer address to exclude (e.g. who sent us the tx)
        """
        for addr, recon in self._erlay_peers.items():
            if addr == exclude_addr:
                continue
            recon.add_tx(txid)

    def is_erlay_peer(self, addr: str) -> bool:
        """Check if a peer has Erlay negotiated."""
        return addr in self._erlay_peers

    def get_erlay_peers(self) -> list[str]:
        """Return addresses of all Erlay-capable peers."""
        return list(self._erlay_peers.keys())

    async def _flood_pending_invs(self, peer: Peer, addr: str) -> None:
        recon = self._erlay_peers.get(addr)
        if recon is None or recon.set_size == 0:
            return
        inv_items = [(INV_TYPE_TX, txid) for txid in list(recon.local_set)]
        if inv_items:
            try:
                inv_msg = InvMessage(inv_items)
                await peer.send_message(
                    inv_msg.to_network_message(self.network)
                )
                logger.debug(
                    f"Flooded {len(inv_items)} INVs to {addr} (fallback)"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to flood INVs to {addr}: {e}"
                )
        # Mark all as announced
        for txid in list(recon.local_set):
            recon.mark_announced(txid)

    def get_best_peer(self) -> Peer | None:
        """
        Get peer with lowest latency.

        Returns:
            Best peer or None if no peers available
        """
        ready_peers = [
            p for p in self.peers.values()
            if p.is_connected()
        ]

        if not ready_peers:
            return None

        # Sort by latency (or score if latency not available)
        return min(
            ready_peers,
            key=lambda p: (
                p.latency if p.latency > 0 else 999,
                -p.score  # Higher score is better
            )
        )

    def get_all_ready_peers(self) -> list[Peer]:
        """
        Get all ready peers (full-relay outbound + block-relay-only + inbound).

        Returns:
            List of connected peers
        """
        all_peers = (
            list(self.peers.values())
            + list(self.block_relay_peers.values())
            + list(self.inbound_peers.values())
        )
        return [p for p in all_peers if p.is_connected()]

    def get_peer_by_addr(self, addr: str) -> Peer | None:
        """
        Get peer by address (searches full-relay, block-relay-only, and inbound).

        Args:
            addr: Peer address (host:port)

        Returns:
            Peer instance or None
        """
        return (
            self.peers.get(addr)
            or self.block_relay_peers.get(addr)
            or self.inbound_peers.get(addr)
        )

    async def broadcast(self, msg: NetworkMessage):
        """
        Broadcast message to all ready peers.

        Args:
            msg: NetworkMessage to broadcast
        """
        ready_peers = self.get_all_ready_peers()
        if not ready_peers:
            logger.warning("No peers available for broadcast")
            return

        # Send to all peers in parallel
        tasks = []
        for peer in ready_peers:
            async def send_to_peer(p):
                try:
                    await p.send_message(msg)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {p.host}:{p.port}: {e}")
                    p.adjust_score(-5)  # Penalize for send failure

            tasks.append(send_to_peer(peer))

        await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug(f"Broadcast {msg.command} to {len(ready_peers)} peers")

    def ban_peer(self, addr: str, duration: int = 86400):
        """
        Ban a peer temporarily.

        Args:
            addr: Peer address (host:port)
            duration: Ban duration in seconds (default: 24 hours)
        """
        self.ban_manager.ban_duration = duration
        self.ban_manager.ban(addr)

    def _on_peer_banned(self, ip: str) -> None:
        """Disconnect peers whose IP has just been banned.

        Applies Core-canonical exemptions from net_processing.cpp
        MaybeDiscourageAndDisconnect @5083:
          1. noban flag set  → skip entirely (whitelisted peer).
          2. is_manual flag set → skip entirely (addnode peer is re-dialed
             on disconnect anyway; banning it permanently is wrong).
          3. Local address    → disconnect only, no discourage.
          4. All others       → disconnect (ban already recorded in ban_manager).
        """
        all_buckets = [
            (self.peers, False),           # full-relay outbound
            (self.block_relay_peers, False),  # block-relay-only outbound
            (self.inbound_peers, True),    # inbound
        ]
        for bucket, _is_inbound in all_buckets:
            matching = [a for a in list(bucket) if a.startswith(ip)]
            for addr in matching:
                peer = bucket.get(addr)
                if peer is None:
                    continue
                # Guard 1: NoBan permission — skip entirely.
                if peer.noban:
                    logger.debug(
                        "_on_peer_banned: skipping noban peer %s", addr
                    )
                    continue
                # Guard 2: Manual (addnode) connection — skip entirely.
                if peer.is_manual:
                    logger.debug(
                        "_on_peer_banned: skipping manual peer %s", addr
                    )
                    continue
                # Guard 3: Local address — disconnect only, no discourage.
                if is_local_addr(peer.host):
                    logger.debug(
                        "_on_peer_banned: local peer %s — disconnect-only", addr
                    )
                    bucket.pop(addr, None)
                    asyncio.ensure_future(peer.disconnect())
                    continue
                # Default: disconnect the peer (ban is already in ban_manager).
                bucket.pop(addr, None)
                asyncio.ensure_future(peer.disconnect())
        self.known_addrs.discard(ip)

    def record_misbehavior(self, addr: str, score: int, reason: str) -> bool:
        """Record misbehavior for a peer; auto-bans at threshold.

        Returns True if the peer was banned.
        """
        return self.ban_manager.record_misbehavior(addr, score, reason)

    def misbehaving(self, peer_id: str, score: int, reason: str) -> bool:
        """Record misbehavior for a peer (Bitcoin Core API compatibility).

        This method adds misbehavior points to a peer. When the cumulative
        score reaches the ban threshold (default 100), the peer is automatically
        disconnected and banned for the ban duration (default 24 hours).

        Common scores (from Bitcoin Core net_processing.cpp):
            - Invalid block: 100 (instant ban)
            - Invalid headers: 20
            - Invalid tx: 10
            - Unrequested data: 20

        Args:
            peer_id: Peer identifier (IP address or IP:port)
            score: Misbehavior score to add
            reason: Human-readable reason

        Returns:
            True if the peer was banned as a result
        """
        return self.ban_manager.misbehaving(peer_id, score, reason)

    def unban_peer(self, addr: str):
        """
        Unban a peer.

        Args:
            addr: Peer address (host:port)
        """
        self.ban_manager.unban(addr)

    def add_peer_address(self, addr: str):
        """
        Add a peer address to known addresses.

        Args:
            addr: Peer address (host:port)
        """
        if not self.ban_manager.is_banned(addr):
            self.known_addrs.add(addr)
            logger.debug(f"Added peer address: {addr}")

    # --- Transaction Trickling (Privacy-Preserving Relay) ---

    async def _trickle_loop(self) -> None:
        """Background loop that sends queued INVs on Poisson-distributed schedule.

        For each peer with a trickle queue, checks if it's time to send INVs
        and dispatches them. Randomized timing prevents network observers from
        correlating transaction broadcasts with originating nodes.
        """
        try:
            while self.running:
                await asyncio.sleep(self._trickle_interval)
                if not self.running:
                    break

                current_time = time.time()

                # Process each peer's trickle queue
                for addr, queue in list(self._trickle_queues.items()):
                    if queue.pending_count == 0:
                        continue

                    # Check if it's time to send
                    if not queue.should_send(current_time):
                        continue

                    peer = self.get_peer_by_addr(addr)
                    if peer is None or not peer.is_connected():
                        # Peer disconnected — clean up
                        self._trickle_queues.pop(addr, None)
                        continue

                    # Skip block-relay-only peers (no tx relay)
                    if not peer.relay_txs:
                        queue.clear()
                        continue

                    try:
                        # Get INVs to send, filtering by peer's feefilter (BIP133)
                        inv_items = queue.get_invs_to_send(
                            feefilter=peer.peer_feefilter
                        )
                        if inv_items:
                            # Send INV message
                            inv_msg = InvMessage(inv_items)
                            await peer.send_message(
                                inv_msg.to_network_message(self.network)
                            )
                            logger.debug(
                                f"Trickled {len(inv_items)} tx INVs to {addr}"
                            )

                        # Schedule next send with Poisson delay
                        queue.schedule_next_send(current_time)

                    except Exception as e:
                        logger.warning(
                            f"Failed to send trickled INVs to {addr}: {e}"
                        )

        except asyncio.CancelledError:
            logger.debug("Trickle loop cancelled")
        except Exception as e:
            logger.error(f"Error in trickle loop: {e}")

    def queue_tx_for_relay(
        self,
        txid: bytes,
        wtxid: bytes,
        fee: int = 0,
        vsize: int = 0,
        exclude_addr: str = "",
    ) -> int:
        """Queue a transaction for trickled announcement to all eligible peers.

        Instead of immediately broadcasting INVs, the transaction is added to
        each peer's trickle queue and announced on a randomized schedule.

        BIP133: Fee information is stored so that transactions can be filtered
        based on each peer's feefilter at announcement time.

        For Erlay-enabled peers, transactions are added to the reconciliation
        set instead of the trickle queue (handled separately).

        Args:
            txid: 32-byte transaction hash
            wtxid: 32-byte witness transaction hash
            fee: Transaction fee in satoshis (for BIP133 feefilter)
            vsize: Virtual size in vbytes (for BIP133 feefilter)
            exclude_addr: Peer address to exclude (sender of the tx)

        Returns:
            Number of peers the transaction was queued for
        """
        queued_count = 0

        # Get all full-relay peers (outbound + inbound)
        all_relay_peers = list(self.peers.items()) + list(self.inbound_peers.items())

        for addr, peer in all_relay_peers:
            if addr == exclude_addr:
                continue
            if not peer.is_connected() or not peer.relay_txs:
                continue

            # For Erlay peers, add to reconciliation set instead
            if self.is_erlay_peer(addr):
                self.erlay_add_tx_to_reconcile(txid, exclude_addr=exclude_addr)
                continue

            # Get or create trickle queue
            queue = self._trickle_queues.get(addr)
            if queue is None:
                queue = TrickleQueue(
                    is_inbound=peer.inbound,
                    wtxid_relay=peer.wtxid_relay,
                )
                self._trickle_queues[addr] = queue

            # Add to trickle queue with fee info for BIP133 filtering
            if queue.add_tx(txid, wtxid, fee=fee, vsize=vsize):
                queued_count += 1

        if queued_count > 0:
            logger.debug(
                f"Queued tx {txid.hex()[:16]}... for trickled relay to "
                f"{queued_count} peers (fee={fee}, vsize={vsize})"
            )

        return queued_count

    def mark_tx_known_by_peer(
        self,
        addr: str,
        txid: bytes,
        wtxid: bytes,
    ) -> None:
        """Mark a transaction as known by a peer (e.g., received from them).

        Prevents us from announcing the transaction back to the peer.

        Args:
            addr: Peer address
            txid: 32-byte transaction hash
            wtxid: 32-byte witness transaction hash
        """
        queue = self._trickle_queues.get(addr)
        if queue is not None:
            queue.mark_known(txid, wtxid)

    def update_peer_wtxid_relay(self, addr: str, wtxid_relay: bool) -> None:
        """Update a peer's wtxid relay preference.

        Called when wtxidrelay message is received during handshake.

        Args:
            addr: Peer address
            wtxid_relay: True if peer supports BIP339 wtxid relay
        """
        queue = self._trickle_queues.get(addr)
        if queue is not None:
            queue.wtxid_relay = wtxid_relay

    def get_trickle_stats(self) -> dict:
        """Get transaction trickling statistics.

        Returns:
            Dictionary with trickle queue stats
        """
        total_pending = sum(q.pending_count for q in self._trickle_queues.values())
        inbound_queues = sum(1 for q in self._trickle_queues.values() if q.is_inbound)
        outbound_queues = len(self._trickle_queues) - inbound_queues

        return {
            "trickle_queues": len(self._trickle_queues),
            "inbound_queues": inbound_queues,
            "outbound_queues": outbound_queues,
            "total_pending": total_pending,
        }

    def get_peer_count(self) -> int:
        """Get total number of connected peers (outbound + block-relay-only + inbound)"""
        return len(self.peers) + len(self.block_relay_peers) + len(self.inbound_peers)

    def get_ready_peer_count(self) -> int:
        """Get number of ready peers"""
        return len(self.get_all_ready_peers())

    def get_time_offset(self) -> int:
        """
        Median clock-skew across connected peers in seconds.

        Matches Bitcoin Core's GetTimeOffset() / getnetworkinfo.timeoffset:
        the median of each peer's handshake-time skew
        (their VERSION.timestamp minus our local time at receipt).
        Returns 0 if no peer has completed a VERSION handshake.
        """
        offsets = [
            p.time_offset
            for p in self.get_all_ready_peers()
            if getattr(p, "_version_received", False)
        ]
        if not offsets:
            return 0
        offsets.sort()
        mid = len(offsets) // 2
        if len(offsets) % 2:
            return offsets[mid]
        # Even count: integer average of the two middle values, rounded toward zero.
        return (offsets[mid - 1] + offsets[mid]) // 2

    def get_stats(self) -> dict:
        """
        Get peer manager statistics.

        Returns:
            Dictionary with statistics
        """
        ready_peers = self.get_all_ready_peers()
        avg_latency = (
            sum(p.latency for p in ready_peers if p.latency > 0) / len(ready_peers)
            if ready_peers else 0
        )
        avg_score = (
            sum(p.score for p in ready_peers) / len(ready_peers)
            if ready_peers else 0
        )

        onion_peers = sum(
            1 for p in ready_peers if is_onion_host(p.host)
        )
        i2p_peers = sum(
            1 for p in ready_peers if is_i2p_host(p.host)
        )

        trickle_stats = self.get_trickle_stats()

        return {
            "connected": len(self.peers) + len(self.block_relay_peers) + len(self.inbound_peers),
            "outbound": len(self.peers),
            "block_relay_only": len(self.block_relay_peers),
            "inbound": len(self.inbound_peers),
            "ready": len(ready_peers),
            "known": len(self.known_addrs),
            "banned": len(self.ban_manager.list_banned()),
            "avg_latency": avg_latency,
            "avg_score": avg_score,
            "erlay_peers": len(self._erlay_peers),
            "erlay_enabled": self.erlay_enabled,
            "proxy": self.proxy,
            "onion_proxy": self.onion,
            "onion_peers": onion_peers,
            "i2p_sam": self.i2psam,
            "i2p_address": self._i2p_address,
            "i2p_peers": i2p_peers,
            "tor_control": self.torcontrol,
            "tor_onion_address": self._tor_onion_address,
            "trickle_pending": trickle_stats["total_pending"],
            # Eclipse protection stats
            "outbound_netgroups": len(self._outbound_netgroups),
            "inbound_netgroups": len(self._inbound_netgroups),
            "anchors": len(self._anchors),
            "addrman_new": self.addrman.new_count(),
            "addrman_tried": self.addrman.tried_count(),
        }


# Alias for backward compatibility
P2PManager = PeerManager
