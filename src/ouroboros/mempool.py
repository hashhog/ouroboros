"""
Transaction mempool management.

This module implements the unconfirmed transaction pool with fee rate
sorting, double spend detection, size management, ancestor/descendant
limits, and standardness checks.
"""

import logging
import os
import random
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ouroboros.database import Transaction
from ouroboros.validation import (
    TransactionValidator,
    WITNESS_SCALE_FACTOR,
    DEFAULT_BYTES_PER_SIGOP,
    get_sigops_adjusted_weight,
    get_virtual_transaction_size,
    _count_legacy_sigops,
    _count_witness_sigops,
    _get_p2sh_sigops,
    _get_last_push,
    _is_p2sh,
)

logger = logging.getLogger(__name__)

OutPoint = tuple[bytes, int]

# Policy constants
MAX_STANDARD_TX_WEIGHT = 400_000
# Maximum sigop cost for a single transaction in the mempool.
# Reference: Bitcoin Core policy/policy.h MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5
MAX_STANDARD_TX_SIGOPS_COST = 16_000
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
MAX_STANDARD_SCRIPTSIG_SIZE = 1650  # Bitcoin Core policy/policy.h MAX_STANDARD_SCRIPTSIG_SIZE
MAX_OP_RETURN_RELAY = 100_000  # MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR (100 kB, policy/policy.h)
MAX_ANCESTOR_COUNT = 25
MAX_DESCENDANT_COUNT = 25
MAX_ANCESTOR_SIZE_KVB = 101
MAX_DESCENDANT_SIZE_KVB = 101
DUST_RELAY_TX_FEE = 3000  # sat/kB
DEFAULT_MIN_RELAY_TX_FEE = 1000  # sat/kvB
# DEFAULT_INCREMENTAL_RELAY_FEE — sat/kvB (policy/policy.h:48)
# This is the minimum fee increment for relay and for trimming.  Bitcoin Core
# sets this to 100 sat/kvB (NOT 1000).  A higher value incorrectly tightens
# RBF gate 4 and inflates the rolling minimum fee after trim.
DEFAULT_INCREMENTAL_RELAY_FEE = 100  # sat/kvB (Core DEFAULT_INCREMENTAL_RELAY_FEE)
# Rolling fee halflife — seconds (txmempool.h:212)
ROLLING_FEE_HALFLIFE = 60 * 60 * 12  # 12 hours = 43200 s
MEMPOOL_EXPIRY_HOURS = 336  # 14 days
TX_MAX_STANDARD_VERSION = 3

# TRUC (v3 transaction) policy constants (Bitcoin Core policy/truc_policy.cpp)
TRUC_VERSION = 3  # nVersion == 3 marks a TRUC transaction
TRUC_MAX_VSIZE = 10_000  # max vsize for any TRUC transaction
TRUC_CHILD_MAX_VSIZE = 1_000  # max vsize for a v3 child spending unconfirmed v3 parent
TRUC_ANCESTOR_LIMIT = 2  # v3 tx may have at most 1 unconfirmed ancestor (self + 1)
TRUC_DESCENDANT_LIMIT = 2  # v3 tx may have at most 1 unconfirmed descendant (self + 1)
TX_V3_ANCESTOR_LIMIT = TRUC_ANCESTOR_LIMIT  # alias used in RBF checks
TX_V3_MAX_VSIZE = TRUC_MAX_VSIZE  # alias used in RBF checks

# Package validation limits (BIP 331)
MAX_PACKAGE_COUNT = 25
MAX_PACKAGE_WEIGHT = 404_000  # weight units

# Cluster mempool limits (Bitcoin Core policy/policy.h + kernel/mempool_limits.h)
# DEFAULT_CLUSTER_LIMIT = 64  (policy/policy.h:72)
# DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101  (policy/policy.h:74)
MAX_CLUSTER_COUNT = 64        # Maximum transactions per cluster (was 100 — WRONG)
MAX_CLUSTER_SIZE_VBYTES = 101_000  # Maximum virtual bytes per cluster (101 kvB)

# Extra descendant tx size limit for package validation (Bitcoin Core policy/policy.h:90)
# EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10000 weight units; governs the one-extra-tx package
# relaxation. Currently informational — kept here to match Core's constant namespace.
EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10_000

# Ephemeral dust policy constants (Bitcoin Core policy/policy.h)
MAX_DUST_OUTPUTS_PER_TX = 1  # Maximum number of dust outputs per transaction

# MAX_P2SH_SIGOPS — Bitcoin Core policy/policy.h:42
# Maximum number of sigops allowed in a P2SH redeem script that is being spent.
# A standard-relay rule (not consensus): a P2SH input whose redeem script
# would execute more than 15 sigops is rejected as non-standard.
MAX_P2SH_SIGOPS = 15

# Witness standardness constants (Bitcoin Core policy/policy.h + script/script.h + script/interpreter.h)
MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600    # policy/policy.h
MAX_STANDARD_P2WSH_STACK_ITEMS = 100     # policy/policy.h
MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80  # policy/policy.h
MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80  # policy/policy.h (BIP 342)
WITNESS_V0_SCRIPTHASH_SIZE = 32          # script/interpreter.h
WITNESS_V1_TAPROOT_SIZE = 32             # script/interpreter.h
ANNEX_TAG = 0x50                         # script/script.h
TAPROOT_LEAF_MASK = 0xfe                 # script/interpreter.h
TAPROOT_LEAF_TAPSCRIPT = 0xc0            # script/interpreter.h (BIP 342 leaf version)


# ═══════════════════════════════════════════════════════════════════════════════
# Cluster Mempool Implementation
#
# A cluster is a connected component in the mempool dependency graph. Transactions
# are connected if one spends from another (parent-child relationship). The cluster
# mempool groups related transactions and uses linearization to determine optimal
# eviction and mining order.
#
# Reference: Bitcoin Core cluster_linearize.h, txgraph.h
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Chunk:
    """A chunk is a group of transactions that are mined together.

    In a linearization, a chunk is an indivisible unit at its combined feerate.
    When mining, we select chunks in decreasing feerate order.
    When evicting, we remove the lowest-feerate chunk.
    """

    txids: set[bytes]
    total_fee: int
    total_size: int

    @property
    def fee_rate(self) -> float:
        """Fee rate of this chunk in sat/vB."""
        return self.total_fee / self.total_size if self.total_size > 0 else 0.0

    def __lt__(self, other: "Chunk") -> bool:
        """Compare chunks by fee rate for sorting."""
        return self.fee_rate < other.fee_rate


@dataclass
class Cluster:
    """A cluster is a connected component of transactions in the mempool.

    Transactions are connected if one spends from another (parent-child).
    Each cluster maintains its own linearization, which determines the order
    transactions should be mined in and which transactions to evict first.

    Reference: Bitcoin Core txgraph.h - TxGraph
    """

    txids: set[bytes]
    # Cached linearization (list of txids in mining order)
    _linearization: list[bytes] | None = field(default=None, repr=False)
    # Cached chunks (groups of txs with combined feerate)
    _chunks: list[Chunk] | None = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.txids, set):
            self.txids = set(self.txids)

    def invalidate_cache(self) -> None:
        """Invalidate cached linearization and chunks."""
        self._linearization = None
        self._chunks = None

    def contains(self, txid: bytes) -> bool:
        """Check if txid is in this cluster."""
        return txid in self.txids

    def size(self) -> int:
        """Number of transactions in this cluster."""
        return len(self.txids)


class ClusterLinearizer:
    """Linearizes a cluster of transactions for optimal mining order.

    The linearization algorithm produces a topologically valid ordering where
    each prefix has a fee rate >= the next prefix. This is done using the
    ancestor-set-based approach:

    1. Repeatedly find the transaction with highest ancestor feerate
    2. Output that transaction and all its ancestors as a "chunk"
    3. Remove them and repeat until empty

    The result is a list of txids in mining order, where earlier transactions
    should be mined before later ones.

    Reference: Bitcoin Core cluster_linearize.h - Linearize()
    """

    def __init__(
        self,
        transactions: dict[bytes, "MempoolEntry"],
    ):
        """Initialize linearizer with mempool transactions.

        Args:
            transactions: Dict mapping txid -> MempoolEntry for all txs in cluster
        """
        self.transactions = transactions

    def _get_ancestor_set_feerate(self, txid: bytes, remaining: set[bytes]) -> float:
        """Compute the ancestor set feerate for a transaction.

        The ancestor set is the transaction plus all its ancestors (within remaining).
        The ancestor set feerate is the total fee divided by total size.
        """
        entry = self.transactions.get(txid)
        if entry is None:
            return 0.0

        # Collect ancestors within remaining set
        ancestors = {txid}
        queue = [txid]
        while queue:
            current = queue.pop()
            current_entry = self.transactions.get(current)
            if current_entry is None:
                continue
            for parent_txid in current_entry.parents:
                if parent_txid in remaining and parent_txid not in ancestors:
                    ancestors.add(parent_txid)
                    queue.append(parent_txid)

        # Compute combined feerate
        total_fee = 0
        total_size = 0
        for anc_txid in ancestors:
            anc_entry = self.transactions.get(anc_txid)
            if anc_entry:
                total_fee += anc_entry.fee
                total_size += anc_entry.size

        return total_fee / total_size if total_size > 0 else 0.0

    def _get_ancestor_set(self, txid: bytes, remaining: set[bytes]) -> set[bytes]:
        """Get the ancestor set for a transaction within remaining."""
        entry = self.transactions.get(txid)
        if entry is None:
            return set()

        ancestors = {txid}
        queue = [txid]
        while queue:
            current = queue.pop()
            current_entry = self.transactions.get(current)
            if current_entry is None:
                continue
            for parent_txid in current_entry.parents:
                if parent_txid in remaining and parent_txid not in ancestors:
                    ancestors.add(parent_txid)
                    queue.append(parent_txid)

        return ancestors

    def linearize(self, cluster_txids: set[bytes]) -> tuple[list[bytes], list[Chunk]]:
        """Linearize a cluster of transactions.

        Returns:
            (linearization, chunks) where:
            - linearization: List of txids in mining order (parents before children)
            - chunks: List of Chunks representing indivisible mining units
        """
        remaining = set(cluster_txids)
        linearization: list[bytes] = []
        chunks: list[Chunk] = []

        while remaining:
            # Find transaction with highest ancestor set feerate
            best_txid = None
            best_feerate = -1.0

            for txid in remaining:
                feerate = self._get_ancestor_set_feerate(txid, remaining)
                if feerate > best_feerate:
                    best_feerate = feerate
                    best_txid = txid

            if best_txid is None:
                # Should not happen, but handle gracefully
                break

            # Get the ancestor set for this transaction
            ancestor_set = self._get_ancestor_set(best_txid, remaining)

            # Topologically sort the ancestor set (parents before children)
            sorted_ancestors = self._topo_sort(ancestor_set)

            # Add to linearization
            linearization.extend(sorted_ancestors)

            # Create a chunk for this ancestor set
            total_fee = 0
            total_size = 0
            for txid in ancestor_set:
                entry = self.transactions.get(txid)
                if entry:
                    total_fee += entry.fee
                    total_size += entry.size

            chunk = Chunk(
                txids=ancestor_set,
                total_fee=total_fee,
                total_size=total_size,
            )

            # Merge with previous chunk if this chunk has higher feerate
            # (this implements the chunking rule from Bitcoin Core)
            while chunks and chunk.fee_rate > chunks[-1].fee_rate:
                prev_chunk = chunks.pop()
                chunk = Chunk(
                    txids=chunk.txids | prev_chunk.txids,
                    total_fee=chunk.total_fee + prev_chunk.total_fee,
                    total_size=chunk.total_size + prev_chunk.total_size,
                )

            chunks.append(chunk)

            # Remove from remaining
            remaining -= ancestor_set

        return linearization, chunks

    def _topo_sort(self, txids: set[bytes]) -> list[bytes]:
        """Topologically sort transactions (parents before children)."""
        # Build in-degree count for each tx (counting only edges within txids)
        in_degree: dict[bytes, int] = dict.fromkeys(txids, 0)

        for txid in txids:
            entry = self.transactions.get(txid)
            if entry:
                for parent_txid in entry.parents:
                    if parent_txid in txids:
                        in_degree[txid] += 1

        # Start with nodes that have no dependencies
        queue = [txid for txid, degree in in_degree.items() if degree == 0]
        result: list[bytes] = []

        while queue:
            # Pick one with no remaining dependencies
            txid = queue.pop(0)
            result.append(txid)

            # Decrease in-degree for children
            entry = self.transactions.get(txid)
            if entry:
                for child_txid in entry.children:
                    if child_txid in in_degree:
                        in_degree[child_txid] -= 1
                        if in_degree[child_txid] == 0:
                            queue.append(child_txid)

        return result


class ClusterManager:
    """Manages clusters of transactions in the mempool.

    This class tracks which transactions belong to which cluster, and provides
    methods for:
    - Finding the cluster a transaction belongs to
    - Merging clusters when a new transaction connects them
    - Splitting clusters when a transaction is removed
    - Getting chunks for eviction and mining

    Reference: Bitcoin Core txgraph.cpp
    """

    def __init__(self, transactions: dict[bytes, "MempoolEntry"]):
        """Initialize cluster manager.

        Args:
            transactions: Reference to mempool's transactions dict
        """
        self.transactions = transactions
        # txid -> cluster_id (arbitrary identifier)
        self._tx_to_cluster: dict[bytes, int] = {}
        # cluster_id -> Cluster
        self._clusters: dict[int, Cluster] = {}
        # Next cluster ID to assign
        self._next_cluster_id = 0

    def _new_cluster_id(self) -> int:
        """Generate a new unique cluster ID."""
        cid = self._next_cluster_id
        self._next_cluster_id += 1
        return cid

    def _find_connected_component(self, start_txid: bytes) -> set[bytes]:
        """Find all transactions connected to start_txid via parent-child links."""
        if start_txid not in self.transactions:
            return set()

        visited: set[bytes] = set()
        queue = [start_txid]

        while queue:
            txid = queue.pop()
            if txid in visited:
                continue
            if txid not in self.transactions:
                continue

            visited.add(txid)
            entry = self.transactions[txid]

            # Add parents and children
            for parent_txid in entry.parents:
                if parent_txid not in visited and parent_txid in self.transactions:
                    queue.append(parent_txid)
            for child_txid in entry.children:
                if child_txid not in visited and child_txid in self.transactions:
                    queue.append(child_txid)

        return visited

    def add_transaction(self, txid: bytes) -> int | None:
        """Add a transaction to the cluster structure.

        This finds the connected component the tx belongs to and either:
        - Creates a new singleton cluster if no connections
        - Adds to existing cluster if one neighbor
        - Merges clusters if multiple neighbors from different clusters

        Returns the cluster ID the transaction was added to, or None if tx not found.
        """
        if txid not in self.transactions:
            return None

        entry = self.transactions[txid]

        # Find which clusters our parents and children belong to
        neighbor_cluster_ids: set[int] = set()
        for parent_txid in entry.parents:
            if parent_txid in self._tx_to_cluster:
                neighbor_cluster_ids.add(self._tx_to_cluster[parent_txid])
        for child_txid in entry.children:
            if child_txid in self._tx_to_cluster:
                neighbor_cluster_ids.add(self._tx_to_cluster[child_txid])

        if not neighbor_cluster_ids:
            # No neighbors - create singleton cluster
            cluster_id = self._new_cluster_id()
            cluster = Cluster(txids={txid})
            self._clusters[cluster_id] = cluster
            self._tx_to_cluster[txid] = cluster_id
            return cluster_id

        elif len(neighbor_cluster_ids) == 1:
            # One neighbor cluster - add to it
            cluster_id = next(iter(neighbor_cluster_ids))
            cluster = self._clusters[cluster_id]
            cluster.txids.add(txid)
            cluster.invalidate_cache()
            self._tx_to_cluster[txid] = cluster_id
            return cluster_id

        else:
            # Multiple neighbor clusters - merge them all
            cluster_ids = list(neighbor_cluster_ids)
            merged_id = cluster_ids[0]
            merged_cluster = self._clusters[merged_id]

            # Add the new transaction
            merged_cluster.txids.add(txid)
            self._tx_to_cluster[txid] = merged_id

            # Merge other clusters into the first
            for cid in cluster_ids[1:]:
                other_cluster = self._clusters.pop(cid)
                for other_txid in other_cluster.txids:
                    merged_cluster.txids.add(other_txid)
                    self._tx_to_cluster[other_txid] = merged_id

            merged_cluster.invalidate_cache()
            return merged_id

    def remove_transaction(self, txid: bytes) -> None:
        """Remove a transaction from the cluster structure.

        This may cause the cluster to split into multiple clusters if the
        removed transaction was connecting different parts.
        """
        if txid not in self._tx_to_cluster:
            return

        old_cluster_id = self._tx_to_cluster.pop(txid)
        old_cluster = self._clusters.get(old_cluster_id)

        if old_cluster is None:
            return

        old_cluster.txids.discard(txid)

        if not old_cluster.txids:
            # Cluster is now empty
            del self._clusters[old_cluster_id]
            return

        # Check if cluster needs to split
        # Find connected components among remaining transactions
        remaining = set(old_cluster.txids)
        components: list[set[bytes]] = []

        while remaining:
            start = next(iter(remaining))
            component = self._find_connected_component_within(start, remaining)
            components.append(component)
            remaining -= component

        if len(components) == 1:
            # No split needed, just invalidate cache
            old_cluster.invalidate_cache()
        else:
            # Split into multiple clusters
            # Reuse old cluster for first component
            old_cluster.txids = components[0]
            old_cluster.invalidate_cache()

            # Create new clusters for other components
            for comp in components[1:]:
                new_cluster_id = self._new_cluster_id()
                new_cluster = Cluster(txids=comp)
                self._clusters[new_cluster_id] = new_cluster
                for comp_txid in comp:
                    self._tx_to_cluster[comp_txid] = new_cluster_id

    def _find_connected_component_within(
        self, start_txid: bytes, within: set[bytes]
    ) -> set[bytes]:
        """Find connected component starting from start_txid, only considering txids in 'within'."""
        if start_txid not in within:
            return set()

        visited: set[bytes] = set()
        queue = [start_txid]

        while queue:
            txid = queue.pop()
            if txid in visited or txid not in within:
                continue

            entry = self.transactions.get(txid)
            if entry is None:
                continue

            visited.add(txid)

            # Add parents and children that are in 'within'
            for parent_txid in entry.parents:
                if parent_txid in within and parent_txid not in visited:
                    queue.append(parent_txid)
            for child_txid in entry.children:
                if child_txid in within and child_txid not in visited:
                    queue.append(child_txid)

        return visited

    def get_cluster(self, txid: bytes) -> Cluster | None:
        """Get the cluster containing a transaction."""
        cluster_id = self._tx_to_cluster.get(txid)
        if cluster_id is None:
            return None
        return self._clusters.get(cluster_id)

    def get_cluster_id(self, txid: bytes) -> int | None:
        """Get the cluster ID for a transaction."""
        return self._tx_to_cluster.get(txid)

    def get_all_clusters(self) -> list[Cluster]:
        """Get all clusters."""
        return list(self._clusters.values())

    def get_chunks(self, cluster: Cluster) -> list[Chunk]:
        """Get chunks for a cluster (cached)."""
        if cluster._chunks is not None:
            return cluster._chunks

        # Linearize and get chunks
        linearizer = ClusterLinearizer(self.transactions)
        _, chunks = linearizer.linearize(cluster.txids)
        cluster._chunks = chunks
        return chunks

    def get_linearization(self, cluster: Cluster) -> list[bytes]:
        """Get linearization for a cluster (cached)."""
        if cluster._linearization is not None:
            return cluster._linearization

        # Linearize
        linearizer = ClusterLinearizer(self.transactions)
        linearization, chunks = linearizer.linearize(cluster.txids)
        cluster._linearization = linearization
        cluster._chunks = chunks
        return linearization

    def get_worst_chunk(self) -> tuple[Chunk, int] | None:
        """Get the lowest-feerate chunk across all clusters.

        Returns (chunk, cluster_id) or None if empty.
        """
        worst_chunk: Chunk | None = None
        worst_cluster_id: int | None = None

        for cluster_id, cluster in self._clusters.items():
            chunks = self.get_chunks(cluster)
            if chunks:
                # Last chunk has lowest feerate (chunks are high-to-low)
                last_chunk = chunks[-1]
                if worst_chunk is None or last_chunk.fee_rate < worst_chunk.fee_rate:
                    worst_chunk = last_chunk
                    worst_cluster_id = cluster_id

        if worst_chunk is None or worst_cluster_id is None:
            return None
        return worst_chunk, worst_cluster_id

    def get_mining_chunks(self) -> list[tuple[Chunk, int]]:
        """Get all chunks across all clusters, sorted by feerate (highest first).

        Returns list of (chunk, cluster_id) tuples.
        """
        all_chunks: list[tuple[Chunk, int]] = []

        for cluster_id, cluster in self._clusters.items():
            chunks = self.get_chunks(cluster)
            for chunk in chunks:
                all_chunks.append((chunk, cluster_id))

        # Sort by feerate, highest first
        all_chunks.sort(key=lambda x: x[0].fee_rate, reverse=True)
        return all_chunks

    def check_cluster_limit(self, txid: bytes) -> tuple[bool, str]:
        """Check if a transaction (already in self.transactions) exceeds cluster limits.

        Enforces both limits from Bitcoin Core policy/policy.h:
          - MAX_CLUSTER_COUNT = 64 transactions
          - MAX_CLUSTER_SIZE_VBYTES = 101,000 virtual bytes

        Returns (ok, error_message).
        """
        if txid not in self.transactions:
            return True, ""

        entry = self.transactions[txid]
        tx_vbytes = entry.size

        # Find which clusters our parents and children belong to
        neighbor_cluster_ids: set[int] = set()
        for parent_txid in entry.parents:
            if parent_txid in self._tx_to_cluster:
                neighbor_cluster_ids.add(self._tx_to_cluster[parent_txid])
        for child_txid in entry.children:
            if child_txid in self._tx_to_cluster:
                neighbor_cluster_ids.add(self._tx_to_cluster[child_txid])

        if not neighbor_cluster_ids:
            # New singleton cluster - always OK
            return True, ""

        # Gate 1: count
        total_count = 1  # The new transaction
        for cid in neighbor_cluster_ids:
            cluster = self._clusters.get(cid)
            if cluster:
                total_count += cluster.size()

        if total_count > MAX_CLUSTER_COUNT:
            return False, (
                f"Transaction would create cluster of {total_count} txs "
                f"exceeding limit {MAX_CLUSTER_COUNT}"
            )

        # Gate 2: vbyte size
        total_vbytes = tx_vbytes
        for cid in neighbor_cluster_ids:
            cluster = self._clusters.get(cid)
            if cluster:
                for ctxid in cluster.txids:
                    e = self.transactions.get(ctxid)
                    if e is not None:
                        total_vbytes += e.size

        if total_vbytes > MAX_CLUSTER_SIZE_VBYTES:
            return False, (
                f"Transaction would create cluster of {total_vbytes} vbytes "
                f"exceeding limit {MAX_CLUSTER_SIZE_VBYTES}"
            )

        return True, ""

    def rebuild(self) -> None:
        """Rebuild all cluster data from scratch.

        Call this after bulk modifications to the mempool.
        """
        self._tx_to_cluster.clear()
        self._clusters.clear()
        self._next_cluster_id = 0

        # Find all connected components
        remaining = set(self.transactions.keys())

        while remaining:
            start = next(iter(remaining))
            component = self._find_connected_component(start)
            component &= remaining  # Only consider remaining txs

            if component:
                cluster_id = self._new_cluster_id()
                cluster = Cluster(txids=component)
                self._clusters[cluster_id] = cluster
                for txid in component:
                    self._tx_to_cluster[txid] = cluster_id
                remaining -= component
            else:
                remaining.discard(start)


# P2A (Pay-to-Anchor) constants
# P2A script: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes total)
# This is a witness v1 program with a 2-byte program, anyone-can-spend
P2A_SCRIPT = bytes([0x51, 0x02, 0x4e, 0x73])
P2A_PROGRAM = bytes([0x4e, 0x73])  # The witness program bytes


def is_pay_to_anchor(script_pubkey: bytes) -> bool:
    """Check if a scriptPubKey is a Pay-to-Anchor (P2A) output.

    P2A pattern: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes total)
    - Byte 0: OP_1 (0x51) - witness version 1
    - Byte 1: OP_PUSHBYTES_2 (0x02)
    - Bytes 2-3: 0x4e73 - the anchor program

    P2A outputs are designed for CPFP fee bumping in Lightning and other
    protocols. They are anyone-can-spend via witness v1 semantics with an
    empty witness.

    Reference: Bitcoin Core script/script.cpp CScript::IsPayToAnchor()
    """
    return (
        len(script_pubkey) == 4
        and script_pubkey[0] == 0x51  # OP_1 (witness v1)
        and script_pubkey[1] == 0x02  # push 2 bytes
        and script_pubkey[2] == 0x4e  # 'N'
        and script_pubkey[3] == 0x73  # 's'
    )


def is_pay_to_anchor_program(version: int, program: bytes) -> bool:
    """Check if a witness program is P2A given version and program bytes."""
    return (
        version == 1
        and len(program) == 2
        and program[0] == 0x4e
        and program[1] == 0x73
    )


def _is_push_only_from(script: bytes, start: int) -> bool:
    """Return True iff every opcode from `start` is a valid push op.

    Mirrors Bitcoin Core's CScript::IsPushOnly / GetScriptOp semantics:
    returns False if a push opcode's data length extends past end-of-script,
    or if a non-push opcode (>= OP_16+1 == 0x61) is encountered.

    Reference: Bitcoin Core script/script.h CScript::IsPushOnly (line ~436),
    script/solver.cpp Solver() nulldata branch (line ~185).
    """
    i = start
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        # Non-push opcode (OP_16 is 0x60, everything above is non-push)
        if op > 0x60:
            return False
        # Inline data push: 0x01–0x4b bytes of data follow
        if 0x01 <= op <= 0x4b:
            i += op
            if i > n:
                return False
        elif op == 0x4c:  # OP_PUSHDATA1: next byte is length
            if i >= n:
                return False
            length = script[i]
            i += 1 + length
            if i > n:
                return False
        elif op == 0x4d:  # OP_PUSHDATA2: next 2 bytes are length (LE)
            if i + 2 > n:
                return False
            length = script[i] | (script[i + 1] << 8)
            i += 2 + length
            if i > n:
                return False
        elif op == 0x4e:  # OP_PUSHDATA4: next 4 bytes are length (LE)
            if i + 4 > n:
                return False
            length = (script[i] | (script[i + 1] << 8) |
                      (script[i + 2] << 16) | (script[i + 3] << 24))
            i += 4 + length
            if i > n:
                return False
        # else: OP_0 (0x00) or OP_1–OP_16 (0x51–0x60) — no data, OK
    return True


def _is_standard_output_type(script_pubkey: bytes) -> bool:
    """Check if a scriptPubKey is a standard output type.

    Standard types:
    - P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
    - P2SH: OP_HASH160 <20 bytes> OP_EQUAL (23 bytes)
    - P2WPKH: OP_0 <20 bytes> (22 bytes)
    - P2WSH: OP_0 <32 bytes> (34 bytes)
    - P2TR: OP_1 <32 bytes> (34 bytes)
    - P2A: OP_1 <2 bytes> (4 bytes)
    - OP_RETURN: OP_RETURN ... (any length) — only if tail is push-only
    - Bare multisig (rare but standard)

    Reference: Bitcoin Core script/solver.cpp Solver()
    """
    if not script_pubkey:
        return False

    # OP_RETURN is standard (nulldata) — but only if the tail bytes are all
    # valid push opcodes. A truncated push (e.g. 6a 09 dead beef — PUSH9 with
    # only 4 data bytes) makes this nonstandard.
    # Reference: Bitcoin Core script/solver.cpp Solver() ~line 185:
    #   if (IsPushOnly(script.begin()+1, script.end())) return TX_NULL_DATA;
    if script_pubkey[0] == 0x6a:
        return _is_push_only_from(script_pubkey, 1)

    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if (len(script_pubkey) == 25 and script_pubkey[0] == 0x76 and
            script_pubkey[1] == 0xa9 and script_pubkey[2] == 0x14 and
            script_pubkey[23] == 0x88 and script_pubkey[24] == 0xac):
        return True

    # P2SH: OP_HASH160 <20> OP_EQUAL
    if (len(script_pubkey) == 23 and script_pubkey[0] == 0xa9 and
            script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87):
        return True

    # P2WPKH: OP_0 <20>
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
        return True

    # P2WSH: OP_0 <32>
    if len(script_pubkey) == 34 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x20:
        return True

    # P2TR: OP_1 <32>
    if len(script_pubkey) == 34 and script_pubkey[0] == 0x51 and script_pubkey[1] == 0x20:
        return True

    # P2A: OP_1 <2>
    if is_pay_to_anchor(script_pubkey):
        return True

    # Bare multisig: OP_m ... OP_n OP_CHECKMULTISIG
    # This is rare but standard. Check for OP_CHECKMULTISIG at end.
    if len(script_pubkey) >= 3 and script_pubkey[-1] == 0xae:
        return True

    return False


def _get_dust_threshold(script_pubkey: bytes) -> int:
    """Get the dust threshold for a given scriptPubKey.

    P2A outputs are exempt from dust (return 0).
    Reference: Bitcoin Core policy/policy.cpp GetDustThreshold()
    """
    # P2A outputs are exempt from dust threshold (anyone-can-spend anchors)
    if is_pay_to_anchor(script_pubkey):
        return 0

    # P2PKH/P2SH cost: 34 + 148 = 182 bytes
    # P2WPKH cost: 31 + 68 = 99 bytes (roughly)
    # P2WSH cost: 43 + 68 = 111 bytes
    # P2TR cost: 43 + 57.5 = 100.5 bytes
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00:
        n_size = 99  # P2WPKH
    elif len(script_pubkey) == 34 and script_pubkey[0] in (0x00, 0x51):
        n_size = 110  # P2WSH or P2TR
    elif len(script_pubkey) == 23 and script_pubkey[0] == 0xa9:
        n_size = 182  # P2SH
    else:
        n_size = 182  # P2PKH and others
    return (n_size * DUST_RELAY_TX_FEE) // 1000


def _has_ephemeral_dust(tx: Transaction) -> list[int]:
    """Return indices of outputs that are dust (below threshold).

    Exemptions (never considered dust):
    - OP_RETURN outputs (unspendable)
    - P2A (Pay-to-Anchor) outputs (allowed at 0 value for CPFP)
    """
    dust_indices: list[int] = []
    for idx, out in enumerate(tx.outputs):
        if not out.script_pubkey:
            continue
        # OP_RETURN is never dust (unspendable)
        if out.script_pubkey[0] == 0x6a:
            continue
        # P2A outputs are exempt from dust (threshold is 0)
        # The _get_dust_threshold function handles this, but we can
        # short-circuit here for clarity
        if is_pay_to_anchor(out.script_pubkey):
            continue
        threshold = _get_dust_threshold(out.script_pubkey)
        if out.value < threshold:
            dust_indices.append(idx)
    return dust_indices


def _check_ephemeral_dust(
    tx: Transaction, fee: int
) -> tuple[bool, str]:
    """Check ephemeral dust policy for a transaction with dust outputs.

    Called when a transaction has dust outputs. Validates:
    1. At most MAX_DUST_OUTPUTS_PER_TX (1) dust output
    2. Transaction must have 0 fee (child provides fees via CPFP)
    3. Dust output must be P2A or a standard output type

    Reference: Bitcoin Core policy/ephemeral_policy.cpp PreCheckEphemeralTx()

    Args:
        tx: Transaction with dust outputs
        fee: Transaction fee in satoshis

    Returns:
        (ok, error_message)
    """
    dust_indices = _has_ephemeral_dust(tx)

    if not dust_indices:
        return True, ""

    # Rule 1: At most 1 dust output per transaction
    if len(dust_indices) > MAX_DUST_OUTPUTS_PER_TX:
        return False, (
            f"tx with dust must have at most {MAX_DUST_OUTPUTS_PER_TX} "
            f"dust output(s), has {len(dust_indices)}"
        )

    # Rule 2: Transaction with dust must have 0 fee
    # "We never want to give incentives to mine this transaction alone"
    if fee != 0:
        return False, "tx with dust output must be 0-fee"

    # Rule 3: Dust output must be P2A or standard type
    for idx in dust_indices:
        out = tx.outputs[idx]
        if not _is_standard_output_type(out.script_pubkey):
            return False, f"dust output at index {idx} is not a standard type"

    return True, ""


def _compute_tx_sigop_cost(
    tx: Transaction,
    utxo_resolver,  # callable(prev_txid: bytes, prev_vout: int) -> dict | None
) -> int:
    """Compute the BIP141-weighted sigop cost for a single transaction.

    Mirrors Bitcoin Core consensus/tx_verify.cpp GetTransactionSigOpCost():
      cost = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR
           + GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR   [non-coinbase]
           + CountWitnessSigOps(...)                                  [non-coinbase]

    Legacy sigops use inaccurate counting (fAccurate=False); P2SH redeem scripts
    and P2WSH witness scripts use accurate counting (fAccurate=True).

    Reference: Bitcoin Core consensus/tx_verify.cpp:143-162
    """
    # Legacy sigops: all inputs + all outputs, inaccurate mode, × WITNESS_SCALE_FACTOR
    legacy = 0
    for out in tx.outputs:
        legacy += _count_legacy_sigops(out.script_pubkey, accurate=False)
    for inp in tx.inputs:
        legacy += _count_legacy_sigops(inp.script_sig, accurate=False)
    cost = legacy * WITNESS_SCALE_FACTOR

    if tx.is_coinbase:
        return cost  # P2SH and witness paths are skipped for coinbase (Core parity)

    # P2SH + witness sigops (non-coinbase only)
    for inp in tx.inputs:
        utxo = utxo_resolver(inp.prev_txid, inp.prev_vout)
        if utxo is None:
            continue
        prev_spk = bytes(utxo["script_pubkey"])

        # P2SH sigops × WITNESS_SCALE_FACTOR
        cost += _get_p2sh_sigops(inp.script_sig, prev_spk) * WITNESS_SCALE_FACTOR

        # Witness sigops × 1 (BIP141 discount)
        witness_spk = prev_spk
        if _is_p2sh(prev_spk):
            redeem = _get_last_push(inp.script_sig)
            if redeem is not None:
                witness_spk = redeem
        cost += _count_witness_sigops(witness_spk, inp.witness)

    return cost


def _validate_inputs_standardness(
    tx: Transaction,
    prev_scripts: dict[int, bytes],
) -> tuple[bool, str]:
    """Validate that every input spends a STANDARD prevout type and, for
    P2SH inputs, that the redeem script does not exceed MAX_P2SH_SIGOPS sigops.

    Mirrors Bitcoin Core policy/policy.cpp ValidateInputsStandardness
    (lines 214-263), which is called from PreChecks (validation.cpp:897) when
    ``require_standard`` is on.  Coinbase txs are exempt.

    Gates enforced (Core parity, in order):
      G1  Every spent prevScript must be a standard output type (Solver result
          != NONSTANDARD).  Rejects spending of arbitrary scripts and
          witness_unknown (anything but P2PKH / P2SH / P2WPKH / P2WSH / P2TR /
          P2A / bare-multisig / OP_RETURN).
      G2  WITNESS_UNKNOWN inputs (witness version 2..16 / non-standard program
          length) are rejected even though they may be IsStandard.
      G3  For P2SH inputs, the redeem script (last push of the scriptSig)
          must not have more than MAX_P2SH_SIGOPS=15 accurately-counted sigops.
          Note: the redeem script *itself* is what's executed under P2SH
          rules; counting must be accurate (per-opcode + CHECKMULTISIG-N).

    Args:
        tx: The transaction being submitted.
        prev_scripts: Mapping of input-index → prevout scriptPubKey.  Inputs
            without a mapping (e.g., orphans) are skipped — the caller is
            responsible for orphan handling.

    Returns:
        (ok, error_message).  error_message follows Core's
        "bad-txns-nonstandard-inputs" debug strings.
    """
    if tx.is_coinbase:
        return True, ""

    for idx, tx_in in enumerate(tx.inputs):
        prev_spk = prev_scripts.get(idx)
        if prev_spk is None:
            # No prevout resolved — caller must reject this earlier.  Skip
            # rather than mis-report a standardness error.
            continue
        prev_spk = bytes(prev_spk)

        # G1: prevScript type must be standard.  We treat
        # _is_standard_output_type() as the Solver-equivalent: it returns
        # True iff the script matches a known standard pattern (P2PKH, P2SH,
        # P2WPKH, P2WSH, P2TR, P2A, bare multisig, OP_RETURN).
        if not _is_standard_output_type(prev_spk):
            # G2 cousin: a witness program with version != 0/1 and a 2..40
            # byte program is technically IsStandard returning WITNESS_UNKNOWN
            # in Core, which is also rejected here.  Since
            # _is_standard_output_type() already returns False for
            # witness_unknown (only OP_0 and OP_1 witness-program versions
            # pass), this branch handles both G1 and G2.
            wp = _get_witness_program(prev_spk)
            if wp is not None:
                ver, _prog = wp
                return False, (
                    f"bad-txns-nonstandard-inputs: input {idx} witness "
                    f"program is undefined (witness version {ver})"
                )
            return False, (
                f"bad-txns-nonstandard-inputs: input {idx} script unknown"
            )

        # G3: P2SH redeem-script sigop limit.
        # P2SH detection: 23 bytes, OP_HASH160 <20> OP_EQUAL.
        if len(prev_spk) == 23 and prev_spk[0] == 0xa9 and prev_spk[22] == 0x87:
            # Extract the redeem script: it's the last data push of scriptSig.
            # Core uses EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE) to
            # derive the full stack; we just take the last push, which is
            # what Core does anyway for the redeem script.
            redeem = _get_last_push(tx_in.script_sig)
            if redeem is None:
                return False, (
                    f"bad-txns-nonstandard-inputs: input {idx} P2SH "
                    f"redeemscript missing"
                )
            # Count sigops in the redeem script accurately (CHECKMULTISIG
            # counts as N when preceded by OP_1..OP_16, else 20).
            redeem_sigops = _count_legacy_sigops(redeem, accurate=True)
            if redeem_sigops > MAX_P2SH_SIGOPS:
                return False, (
                    f"bad-txns-nonstandard-inputs: input {idx} P2SH "
                    f"redeemscript sigops {redeem_sigops} > "
                    f"{MAX_P2SH_SIGOPS} (MAX_P2SH_SIGOPS)"
                )

    return True, ""


def _is_standard_tx(tx: Transaction) -> tuple[bool, str]:
    """Check transaction standardness against Bitcoin Core policy gates.

    Mirrors Bitcoin Core policy/policy.cpp IsStandardTx() and the
    additional pre-checks in validation.cpp AcceptToMemoryPoolWorker().

    Gates (in Core order):
      1. Version ∈ [1, TX_MAX_STANDARD_VERSION]
      2. Weight ≤ MAX_STANDARD_TX_WEIGHT (400 000 WU)
      3. Non-witness size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes)
         — CVE-2017-12842 mitigation (validation.cpp:813)
      4. Per-input: scriptSig size ≤ MAX_STANDARD_SCRIPTSIG_SIZE (1650 B)
      5. Per-input: scriptSig is push-only
      6. Per-output: scriptPubKey is a standard type
      7. Cumulative OP_RETURN (nulldata) payload ≤ MAX_OP_RETURN_RELAY bytes
      8. Dust check (skipped for v3 which uses ephemeral-dust rules)
    """
    if tx.version < 1 or tx.version > TX_MAX_STANDARD_VERSION:
        return False, f"Non-standard version: {tx.version}"

    # Gate 2: weight.  Use the real BIP-141 weight formula (stripped_size × 3 +
    # total_size) rather than the previous stripped_size × 4 approximation,
    # which over-counts for segwit transactions and incorrectly rejects large
    # segwit txs that Core accepts.
    # Reference: Bitcoin Core policy/policy.cpp IsStandardTx() ~line 111-115.
    tx_weight = tx.get_weight()
    if tx_weight > MAX_STANDARD_TX_WEIGHT:
        return False, f"Transaction weight {tx_weight} exceeds {MAX_STANDARD_TX_WEIGHT}"

    # Gate 3: minimum non-witness size (CVE-2017-12842).
    # tx.serialize() returns stripped (no-witness) bytes, matching TX_NO_WITNESS.
    # Reference: Bitcoin Core validation.cpp:813.
    tx_size = len(tx.serialize())
    if tx_size < MIN_STANDARD_TX_NONWITNESS_SIZE:
        return False, f"Transaction too small: {tx_size} < {MIN_STANDARD_TX_NONWITNESS_SIZE}"

    # Gates 4 + 5: per-input scriptSig checks.
    # Reference: Bitcoin Core policy/policy.cpp IsStandardTx() ~line 117-135:
    #   if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) → "scriptsig-size"
    #   if (!txin.scriptSig.IsPushOnly())                        → "scriptsig-not-pushonly"
    for idx, tx_in in enumerate(tx.inputs):
        if len(tx_in.script_sig) > MAX_STANDARD_SCRIPTSIG_SIZE:
            return False, f"Input {idx} scriptSig size {len(tx_in.script_sig)} exceeds {MAX_STANDARD_SCRIPTSIG_SIZE} (scriptsig-size)"
        if tx_in.script_sig and not _is_push_only_from(tx_in.script_sig, 0):
            return False, f"Input {idx} scriptSig is not push-only (scriptsig-not-pushonly)"

    # Gates 6 + 7: per-output type + cumulative datacarrier limit.
    # Reference: Bitcoin Core policy/policy.cpp IsStandardTx() ~line 137-156:
    #   IsStandard(txout.scriptPubKey, whichType) → "scriptpubkey"
    #   NULL_DATA cumulative size > max_datacarrier_bytes → "datacarrier"
    # MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100 000 bytes.
    datacarrier_bytes_used = 0
    for idx, out in enumerate(tx.outputs):
        if not _is_standard_output_type(out.script_pubkey):
            return False, f"Output {idx} has non-standard script type (scriptpubkey)"
        # Track cumulative OP_RETURN payload bytes.
        if out.script_pubkey and out.script_pubkey[0] == 0x6a:
            datacarrier_bytes_used += len(out.script_pubkey)
            if datacarrier_bytes_used > MAX_OP_RETURN_RELAY:
                return False, (
                    f"Total OP_RETURN data {datacarrier_bytes_used} bytes exceeds "
                    f"{MAX_OP_RETURN_RELAY} (datacarrier)"
                )

    # Gate 8: dust output cap.
    # Reference: Bitcoin Core policy/policy.cpp IsStandardTx() lines 158-162:
    #   if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) → "dust"
    # MAX_DUST_OUTPUTS_PER_TX = 1.  Up to one dust output is allowed at this
    # gate; the additional rule that a fee-paying tx may not have any dust
    # output is enforced separately by PreCheckEphemeralTx after the fee is
    # known (called from _add_transaction_inner).  v3 transactions submitted
    # individually are rejected earlier in _add_transaction_inner.
    # Prior to this fix this gate rejected any tx with one or more dust
    # outputs, which is stricter than Core (Core allows exactly one).
    if tx.version != 3:
        dust_indices = _has_ephemeral_dust(tx)
        if len(dust_indices) > MAX_DUST_OUTPUTS_PER_TX:
            return False, (
                f"dust: {len(dust_indices)} dust output(s) exceeds "
                f"MAX_DUST_OUTPUTS_PER_TX ({MAX_DUST_OUTPUTS_PER_TX})"
            )

    return True, ""


def _eval_script_sig_to_stack(script_sig: bytes) -> list[bytes] | None:
    """Evaluate a scriptSig into its push-data stack (SCRIPT_VERIFY_NONE semantics).

    Mirrors Bitcoin Core EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...) as used
    in IsWitnessStandard to extract the redeemScript from a P2SH input.  We do not
    enforce push-only here — that is checked separately by _is_standard_tx gate 5.
    Returns None if parsing fails (malformed script), otherwise the stack.

    Reference: bitcoin-core/src/policy/policy.cpp IsWitnessStandard() line 293.
    """
    stack: list[bytes] = []
    i = 0
    n = len(script_sig)
    while i < n:
        op = script_sig[i]
        i += 1
        if op == 0x00:
            # OP_0 — push empty bytes
            stack.append(b"")
        elif 0x01 <= op <= 0x4b:
            # Inline push: op bytes of data
            if i + op > n:
                return None  # truncated
            stack.append(script_sig[i:i + op])
            i += op
        elif op == 0x4c:  # OP_PUSHDATA1
            if i >= n:
                return None
            length = script_sig[i]
            i += 1
            if i + length > n:
                return None
            stack.append(script_sig[i:i + length])
            i += length
        elif op == 0x4d:  # OP_PUSHDATA2
            if i + 2 > n:
                return None
            length = script_sig[i] | (script_sig[i + 1] << 8)
            i += 2
            if i + length > n:
                return None
            stack.append(script_sig[i:i + length])
            i += length
        elif op == 0x4e:  # OP_PUSHDATA4
            if i + 4 > n:
                return None
            length = (script_sig[i] | (script_sig[i + 1] << 8) |
                      (script_sig[i + 2] << 16) | (script_sig[i + 3] << 24))
            i += 4
            if i + length > n:
                return None
            stack.append(script_sig[i:i + length])
            i += length
        elif 0x51 <= op <= 0x60:
            # OP_1 through OP_16
            stack.append(bytes([op - 0x50]))
        elif op == 0x4f:
            # OP_1NEGATE
            stack.append(b"\x81")
        else:
            # Non-push opcode — skip (SCRIPT_VERIFY_NONE does not enforce push-only)
            # We're just extracting the stack; these won't be present in well-formed P2SH.
            pass
    return stack


def _get_witness_program(script_pubkey: bytes) -> tuple[int, bytes] | None:
    """Extract (version, program) from a witness program scriptPubKey.

    Returns None if script_pubkey is not a witness program (OP_0/OP_1–16 + 2–40 push).
    Mirrors Bitcoin Core CScript::IsWitnessProgram().

    Reference: bitcoin-core/src/script/script.cpp CScript::IsWitnessProgram().
    """
    if len(script_pubkey) < 4 or len(script_pubkey) > 42:
        return None
    version_opcode = script_pubkey[0]
    if version_opcode == 0x00:
        version = 0
    elif 0x51 <= version_opcode <= 0x60:
        version = version_opcode - 0x50
    else:
        return None
    # Second byte must encode the program length
    program_len = script_pubkey[1]
    if program_len + 2 != len(script_pubkey):
        return None
    if program_len < 2 or program_len > 40:
        return None
    return version, script_pubkey[2:]


def _is_witness_standard(
    tx: "Transaction",
    prevscripts: dict[int, bytes],
) -> tuple[bool, str]:
    """Check witness standardness for a transaction.

    Mirrors Bitcoin Core IsWitnessStandard() (policy/policy.cpp lines 265-352).
    `prevscripts` maps input index → scriptPubKey bytes for every input that has
    a non-null witness.  Inputs absent from the map are assumed to have an empty
    witness and are skipped.

    Gates enforced (numbered as in the Bitcoin Core source):
      G1  Coinbase exempt (line 267-268).
      G2  Empty witness inputs are skipped (line 274-275).
      G3  P2A input with any witness → "bad-witness-nonstandard" (line 283-285).
      G4  P2SH-wrapped witness: eval scriptSig push-stack → top = redeemScript;
          fail/empty stack → "bad-witness-nonstandard" (lines 288-299).
      G5  Non-witness prevScript paired with non-empty witness →
          "bad-witness-nonstandard" (lines 305-306).
      G6  P2WSH (v0, 32-byte program) resource limits (lines 309-318):
          - last stack item (witnessScript) ≤ 3600 bytes
          - stack items excluding script ≤ 100
          - each non-script item ≤ 80 bytes
      G7  P2TR (v1, 32-byte program, NOT P2SH-wrapped) limits (lines 321-349):
          - annex (stack[-1][0] == 0x50) present → "bad-witness-nonstandard"
          - script-path: per tapscript-item size ≤ 80 bytes
          - 0-item stack → "bad-witness-nonstandard" (consensus-invalid anyway)

    Reference: bitcoin-core/src/policy/policy.cpp IsWitnessStandard() lines 265-352.
    """
    # G1: coinbase transactions are exempt (line 267-268)
    if tx.is_coinbase:
        return True, ""

    for i, tx_in in enumerate(tx.inputs):
        witness = tx_in.witness  # list[bytes] | None
        # G2: skip inputs with empty/null witness (line 274-275)
        if not witness:
            continue

        prev_script = prevscripts.get(i)
        if prev_script is None:
            # prevScript not provided — caller should provide it for all
            # witness-bearing inputs; skip defensively rather than crash.
            continue

        # G3: P2A input with witness → witness stuffing (line 283-285)
        if is_pay_to_anchor(prev_script):
            return False, "bad-witness-nonstandard"

        # G4: P2SH-wrapped witness path (lines 288-299)
        p2sh = False
        working_script = prev_script
        if (len(prev_script) == 23 and prev_script[0] == 0xa9 and
                prev_script[1] == 0x14 and prev_script[22] == 0x87):
            # prevScript is P2SH — eval scriptSig push stack to get redeemScript
            stack = _eval_script_sig_to_stack(tx_in.script_sig)
            if stack is None or len(stack) == 0:
                return False, "bad-witness-nonstandard"
            working_script = stack[-1]  # redeemScript = top of scriptSig stack
            p2sh = True

        # G5: non-witness prevScript with non-empty witness (lines 305-306)
        wp = _get_witness_program(working_script)
        if wp is None:
            return False, "bad-witness-nonstandard"

        version, program = wp

        # G6: P2WSH (v0, 32-byte program) resource limits (lines 309-318)
        if version == 0 and len(program) == WITNESS_V0_SCRIPTHASH_SIZE:
            # Last witness item is the witnessScript
            witness_script = witness[-1]
            if len(witness_script) > MAX_STANDARD_P2WSH_SCRIPT_SIZE:
                return False, "bad-witness-nonstandard"
            # Stack items excluding the script
            stack_items = witness[:-1]
            if len(stack_items) > MAX_STANDARD_P2WSH_STACK_ITEMS:
                return False, "bad-witness-nonstandard"
            for item in stack_items:
                if len(item) > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE:
                    return False, "bad-witness-nonstandard"

        # G7: P2TR (v1, 32-byte program, NOT P2SH-wrapped) limits (lines 321-349)
        if version == 1 and len(program) == WITNESS_V1_TAPROOT_SIZE and not p2sh:
            stack = list(witness)  # mutable copy; we pop from back
            # Annex check: if stack[-1][0] == ANNEX_TAG and len >= 2 → reject
            if len(stack) >= 2 and stack[-1] and stack[-1][0] == ANNEX_TAG:
                return False, "bad-witness-nonstandard"
            if len(stack) >= 2:
                # Script-path spend: control block = stack[-1], script = stack[-2]
                control_block = stack[-1]
                stack.pop()
                stack.pop()  # discard script
                if not control_block:
                    return False, "bad-witness-nonstandard"
                if (control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT:
                    # Leaf version 0xc0: BIP 342 tapscript stack item size limit
                    for item in stack:
                        if len(item) > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE:
                            return False, "bad-witness-nonstandard"
            elif len(stack) == 1:
                # Key-path spend: single stack element, no policy limits
                pass
            else:
                # 0 elements: consensus-invalid (line 346-348)
                return False, "bad-witness-nonstandard"

    return True, ""


@dataclass
class MempoolEntry:
    """Entry in the mempool.

    Tracks both raw byte size (for mempool byte-budget accounting) and the
    sigop-adjusted virtual size (vsize) used for fee-rate checks, TRUC limits,
    and RPC reporting — matching Bitcoin Core's CTxMemPoolEntry::GetTxSize().

    Reference: bitcoin-core/src/kernel/mempool_entry.h:110-113
        int32_t GetTxSize() const {
            return GetVirtualTransactionSize(nTxWeight, sigOpCost, ::nBytesPerSigOp);
        }
    """
    tx: Transaction
    fee: int
    fee_rate: float  # sat/vbyte (computed from sigop-adjusted vsize)
    size: int        # stripped (no-witness) byte count — for mempool byte budget
    time_added: float
    height_added: int
    sigop_cost: int = 0  # BIP-141-weighted sigop cost (set at admission time)
    ancestor_count: int = 1
    ancestor_size: int = 0
    descendant_count: int = 1
    descendant_size: int = 0
    # Parent/child txid links for efficient graph traversal
    parents: set[bytes] = field(default_factory=set)
    children: set[bytes] = field(default_factory=set)
    # Ephemeral dust tracking: if this tx has ephemeral dust, track the
    # child that spends it. If child is evicted, this parent must be too.
    # Reference: Bitcoin Core policy/ephemeral_policy.cpp
    has_ephemeral_dust: bool = False
    ephemeral_child: bytes | None = None  # txid of child spending our dust

    @property
    def vsize(self) -> int:
        """Sigop-adjusted virtual size in bytes.

        Mirrors Bitcoin Core CTxMemPoolEntry::GetTxSize():
            GetVirtualTransactionSize(nTxWeight, sigOpCost, ::nBytesPerSigOp)

        This is the effective size used for:
          - fee-rate calculation and relay checks
          - TRUC (v3) size limits
          - RPC `sendrawtransaction` / `testmempoolaccept` vsize field
          - ancestor/descendant size accounting (ideally; see inline comment)

        Reference: bitcoin-core/src/kernel/mempool_entry.h:110-113,
                   bitcoin-core/src/policy/policy.cpp:395-403.
        """
        weight = self.tx.get_weight()
        return get_virtual_transaction_size(weight, self.sigop_cost, DEFAULT_BYTES_PER_SIGOP)


# Orphan transaction pool
MAX_ORPHAN_TRANSACTIONS = 100
ORPHAN_EXPIRY_SECONDS = 20 * 60  # 20 minutes


class OrphanPool:
    """Pool of transactions whose parent outputs are not yet available.

    When a transaction references UTXOs that are neither in the chain nor
    in the mempool, it is stored here until the missing parents arrive.

    BIP-339 / Core #22677: primary key is wtxid so that two malleable
    variants of the same txid (same non-witness data, different witness)
    are stored separately.  A secondary txid→wtxid index lets callers
    perform the child-lookup by txid (prevout resolution uses txid).
    """

    def __init__(self):
        # orphan wtxid → (Transaction, expiry_time, set of missing parent txids)
        self.orphans: dict[bytes, tuple[Transaction, float, set[bytes]]] = {}
        # secondary: txid → set of wtxids (one txid may have multiple witness variants)
        self.txid_to_wtxids: dict[bytes, set[bytes]] = {}
        # missing parent txid → set of orphan wtxids waiting on it
        self.by_parent: dict[bytes, set[bytes]] = {}

    def add(self, tx: Transaction, missing_parents: set[bytes]) -> bool:
        """Add an orphan transaction.  Returns True if added.

        Keyed by wtxid (BIP-339): two transactions with the same txid but
        different witness data are stored as separate orphans.
        """
        wtxid = tx.get_wtxid()
        if wtxid in self.orphans:
            return False
        if len(self.orphans) >= MAX_ORPHAN_TRANSACTIONS:
            self._evict_random()
        expiry = time.time() + ORPHAN_EXPIRY_SECONDS
        self.orphans[wtxid] = (tx, expiry, missing_parents)
        txid = tx.get_txid()
        self.txid_to_wtxids.setdefault(txid, set()).add(wtxid)
        for parent in missing_parents:
            self.by_parent.setdefault(parent, set()).add(wtxid)
        logger.debug(
            f"Added orphan tx wtxid={wtxid.hex()[:16]}... txid={txid.hex()[:16]}... "
            f"(missing {len(missing_parents)} parent(s), "
            f"pool size {len(self.orphans)})"
        )
        return True

    def remove(self, wtxid: bytes) -> None:
        """Remove an orphan by wtxid (primary key)."""
        entry = self.orphans.pop(wtxid, None)
        if entry is None:
            return
        tx, _, missing = entry
        txid = tx.get_txid()
        wtxid_set = self.txid_to_wtxids.get(txid)
        if wtxid_set:
            wtxid_set.discard(wtxid)
            if not wtxid_set:
                del self.txid_to_wtxids[txid]
        for parent in missing:
            s = self.by_parent.get(parent)
            if s:
                s.discard(wtxid)
                if not s:
                    del self.by_parent[parent]

    def remove_by_txid(self, txid: bytes) -> None:
        """Remove all orphan entries with the given txid (secondary-index lookup)."""
        wtxids = list(self.txid_to_wtxids.get(txid, set()))
        for wtxid in wtxids:
            self.remove(wtxid)

    def get_orphans_for_parent(self, parent_txid: bytes) -> list[Transaction]:
        """Return orphan txs that are waiting on *parent_txid*."""
        orphan_wtxids = self.by_parent.get(parent_txid, set())
        result = []
        for oid in list(orphan_wtxids):
            entry = self.orphans.get(oid)
            if entry:
                result.append(entry[0])
        return result

    def has(self, txid: bytes) -> bool:
        """Check whether any orphan with the given txid is present (secondary index)."""
        return txid in self.txid_to_wtxids

    def has_wtxid(self, wtxid: bytes) -> bool:
        """Check whether an orphan with the given wtxid is present (primary key)."""
        return wtxid in self.orphans

    def expire(self) -> int:
        """Remove expired orphans.  Returns count removed."""
        now = time.time()
        expired = [
            wtxid for wtxid, (_, exp, _) in self.orphans.items()
            if now >= exp
        ]
        for wtxid in expired:
            self.remove(wtxid)
        if expired:
            logger.debug(f"Expired {len(expired)} orphan transaction(s)")
        return len(expired)

    def size(self) -> int:
        return len(self.orphans)

    def _evict_random(self) -> None:
        if not self.orphans:
            return
        victim = random.choice(list(self.orphans))
        logger.debug(f"Evicting random orphan wtxid={victim.hex()[:16]}...")
        self.remove(victim)


class Mempool:
    """Unconfirmed transaction pool"""

    def __init__(
        self,
        validator: TransactionValidator,
        max_size: int = 300_000_000,  # 300 MB
        require_standard: bool = True,
        full_rbf: bool = True,  # BIP125 Full RBF (mempoolfullrbf), default True since v28
        on_tx_removed: Callable | None = None,  # callback: (txid, reason) -> None
        on_tx_added: Callable | None = None,  # callback: (txid, tx, mempool_seq) -> None
    ):
        """Initialize mempool.

        Args:
            validator: Transaction validator instance
            max_size: Maximum mempool size in bytes (default 300MB)
            require_standard: Enforce standardness rules (default True)
            full_rbf: Enable full RBF - allow replacing any unconfirmed tx
                      regardless of BIP125 signaling (default True since v28)
            on_tx_removed: Optional callback invoked when tx is removed from mempool
                           Called with (txid: bytes, reason: str, mempool_seq: int)
            on_tx_added: Optional callback invoked when tx is added to mempool
                         Called with (txid: bytes, tx: Transaction, mempool_seq: int)
        """
        self.validator = validator
        self.max_size = max_size
        self.require_standard = require_standard
        self.full_rbf = full_rbf
        self._on_tx_removed = on_tx_removed
        self._on_tx_added = on_tx_added

        self.transactions: dict[bytes, MempoolEntry] = {}  # txid -> entry
        # BIP 152 / BIP 339 dual index: keep a wtxid->txid map alongside the
        # txid->entry table.  Every entry is registered in both maps in
        # add/remove/clear; the cmpctblock path uses this to look up txs by
        # short-id without a per-call O(N) scan.  Reference: txmempool.h —
        # mapTx is keyed by txid AND wtxid in Bitcoin Core.
        self.wtxid_to_txid: dict[bytes, bytes] = {}
        self.spent_outputs: set[OutPoint] = set()

        # Sorted by fee rate (for mining)
        self.by_fee_rate: list[bytes] = []  # txids sorted by fee rate (lowest first)

        # Tracking
        self.current_size = 0  # bytes

        # Monotonically increasing mempool sequence number for ZMQ notifications
        # Incremented on every add or remove, providing a total ordering of events
        # Reference: Bitcoin Core txmempool.h m_sequence_number
        self._mempool_sequence: int = 0

        # Rolling minimum fee rate state (txmempool.h:195-197 + txmempool.cpp:829-859)
        # After TrimToSize evicts transactions the rolling minimum rises to
        # evicted_feerate + INCREMENTAL_RELAY_FEE so that evicted txs cannot
        # immediately re-enter.  It decays exponentially with halflife 12 h.
        # blockSinceLastRollingFeeBump is set True on each block; when True the
        # fee can decay; when False (eviction just happened) it is locked.
        self._rolling_minimum_fee_rate: float = 0.0   # sat/kvB as float
        self._last_rolling_fee_update: float = time.time()
        self._block_since_last_rolling_fee_bump: bool = False

        # Reentrant lock for snapshot isolation (e.g. getblocktemplate).
        # RLock because _resolve_orphans -> add_transaction recurses.
        self._lock = threading.RLock()

        # Orphan transaction pool
        self.orphan_pool = OrphanPool()

        # Cluster mempool manager
        self._cluster_manager = ClusterManager(self.transactions)

        # mapDeltas — per-tx fee-priority delta set by prioritisetransaction.
        # txid -> nFeeDelta (satoshis, may be negative).  Persisted across
        # restart via mempool.dat dump/load (FIX-76, Core parity:
        # node/mempool_persist.cpp:101+166-203).  In-mempool entries are
        # written via the per-tx nFeeDelta field; standalone deltas (for
        # txids not currently in the mempool) ride along in the tail block.
        # All fee comparisons that drive mining selection, RBF Rule 3/4 admission,
        # and mempool min-fee use get_modified_fee(entry) = entry.fee + delta.
        # Reference: bitcoin-core/src/txmempool.{h,cpp} PrioritiseTransaction,
        #            mapDeltas, ApplyDelta, GetModifiedFee.
        self.map_deltas: dict[bytes, int] = {}

    def __len__(self) -> int:
        """Return the number of transactions in the mempool."""
        return len(self.transactions)

    @property
    def total_size(self) -> int:
        """Alias for current_size (total bytes in mempool)."""
        return self.current_size

    @property
    def mempool_sequence(self) -> int:
        """Current mempool sequence number."""
        return self._mempool_sequence

    def _next_sequence(self) -> int:
        """Get the next mempool sequence number and increment."""
        seq = self._mempool_sequence
        self._mempool_sequence += 1
        return seq

    # ── Rolling Minimum Fee Rate (txmempool.cpp:829-859) ─────────────────────

    def get_min_fee(self) -> float:
        """Return the current rolling minimum fee rate in sat/kvB.

        Mirrors Bitcoin Core CTxMemPool::GetMinFee(sizelimit).
        Reference: txmempool.cpp:829-851.

        The fee decays exponentially when a block has been seen since the last
        bump (blockSinceLastRollingFeeBump=True).  Halflife is accelerated to
        ROLLING_FEE_HALFLIFE/4 when mempool < sizelimit/4, and to
        ROLLING_FEE_HALFLIFE/2 when mempool < sizelimit/2.

        Returns 0.0 when the rolling rate has decayed below
        incremental_relay_feerate/2, otherwise returns
        max(rolling_rate, INCREMENTAL_RELAY_FEE).
        """
        with self._lock:
            return self._get_min_fee_inner()

    def _get_min_fee_inner(self) -> float:
        """Unlocked implementation of get_min_fee."""
        if not self._block_since_last_rolling_fee_bump or self._rolling_minimum_fee_rate == 0.0:
            return self._rolling_minimum_fee_rate

        now = time.time()
        if now > self._last_rolling_fee_update + 10:
            halflife = ROLLING_FEE_HALFLIFE
            usage = self.current_size
            sizelimit = self.max_size
            if usage < sizelimit / 4:
                halflife /= 4
            elif usage < sizelimit / 2:
                halflife /= 2

            elapsed = now - self._last_rolling_fee_update
            self._rolling_minimum_fee_rate = (
                self._rolling_minimum_fee_rate / (2.0 ** (elapsed / halflife))
            )
            self._last_rolling_fee_update = now

            # Below half the incremental relay fee → treat as zero
            if self._rolling_minimum_fee_rate < DEFAULT_INCREMENTAL_RELAY_FEE / 2.0:
                self._rolling_minimum_fee_rate = 0.0
                return 0.0

        return max(self._rolling_minimum_fee_rate, float(DEFAULT_INCREMENTAL_RELAY_FEE))

    def _track_package_removed(self, fee_per_kvb: float) -> None:
        """Track the fee rate of an evicted package (txmempool.cpp:853-859).

        Bumps rolling_minimum_fee_rate to *fee_per_kvb* if it is higher than
        the current value, and clears block_since_last_rolling_fee_bump so the
        rate is locked (not decaying) until the next block.
        """
        if fee_per_kvb > self._rolling_minimum_fee_rate:
            self._rolling_minimum_fee_rate = fee_per_kvb
            self._block_since_last_rolling_fee_bump = False

    def snapshot(self) -> tuple[list[bytes], dict[bytes, "MempoolEntry"]]:
        """Take a consistent snapshot of the mempool for template construction.

        Returns a copy of (by_fee_rate, transactions) under the lock so that
        concurrent mutations cannot produce an inconsistent view.
        """
        with self._lock:
            fee_rate_copy = list(self.by_fee_rate)
            txs_copy = dict(self.transactions)
        return fee_rate_copy, txs_copy

    # ── PrioritiseTransaction / mapDeltas / modified-fee accounting ─────────
    # Core:
    #   bitcoin-core/src/txmempool.{h,cpp} CTxMemPool::PrioritiseTransaction,
    #   ApplyDelta, ClearPrioritisation, GetPrioritisedTransactions, mapDeltas.
    #   bitcoin-core/src/kernel/mempool_entry.h GetModifiedFee = m_modified_fee.
    # Delta is consulted everywhere Core uses GetModifiedFee() and persists
    # across restart via dump_to_file/load_from_file (FIX-76, Core parity):
    #   - RBF Rule 3/4 PaysForRBF gates (policy/rbf.cpp lines 107-122),
    #   - admission rolling-min-fee + min-relay gates,
    #   - mining selection (by_fee_rate sort effectively uses raw fee_rate;
    #     get_modified_fee_rate() returns the priority-adjusted rate),
    #   - getmempoolentry / getrawmempool RPC `fees.modified` field,
    #   - getprioritisedtransactions RPC.
    #
    # Saturating add semantics match Core (txmempool.cpp:635 SaturatingAdd).
    # A delta of zero removes the entry from map_deltas (Core also erases the
    # entry when the resulting accumulated delta == 0; txmempool.cpp:644-646).

    _DELTA_MAX = (1 << 63) - 1
    _DELTA_MIN = -(1 << 63)

    @staticmethod
    def _saturating_add(a: int, b: int) -> int:
        """Saturating int64 add (mirrors Core util::SaturatingAdd)."""
        s = a + b
        if s > Mempool._DELTA_MAX:
            return Mempool._DELTA_MAX
        if s < Mempool._DELTA_MIN:
            return Mempool._DELTA_MIN
        return s

    def prioritise_transaction(self, txid: bytes, delta_sats: int) -> None:
        """Apply a fee-priority delta for *txid* (Core: PrioritiseTransaction).

        Accumulates onto any existing delta (saturating int64 add).  Calling
        with ``delta_sats == 0`` is a no-op unless the resulting accumulated
        delta becomes zero, in which case the entry is removed (matches Core
        txmempool.cpp:644-653).

        ``txid`` may name a transaction not currently in the mempool: Core
        stores the delta anyway so that if the tx later arrives it will be
        prioritised.  We follow the same semantics.

        Reference: bitcoin-core/src/txmempool.cpp:630-655.
        """
        with self._lock:
            current = self.map_deltas.get(txid, 0)
            new_delta = self._saturating_add(current, int(delta_sats))
            if new_delta == 0:
                self.map_deltas.pop(txid, None)
                logger.info(
                    "PrioritiseTransaction: %s (%sin mempool) delta cleared",
                    txid[::-1].hex(),
                    "" if txid in self.transactions else "not ",
                )
            else:
                self.map_deltas[txid] = new_delta
                logger.info(
                    "PrioritiseTransaction: %s (%sin mempool) fee += %d, new delta=%d",
                    txid[::-1].hex(),
                    "" if txid in self.transactions else "not ",
                    int(delta_sats),
                    new_delta,
                )

    def get_modified_fee(self, txid_or_entry) -> int:
        """Return entry.fee + map_deltas[txid] (Core CTxMemPoolEntry::GetModifiedFee).

        Accepts either a txid (bytes) or a MempoolEntry.  Used by RBF Rule 3/4,
        mining selection, and getmempoolentry RPC.
        """
        if isinstance(txid_or_entry, (bytes, bytearray, memoryview)):
            txid = bytes(txid_or_entry)
            entry = self.transactions.get(txid)
            if entry is None:
                return 0
        else:
            entry = txid_or_entry
            txid = entry.tx.get_txid()
        return int(entry.fee) + int(self.map_deltas.get(txid, 0))

    def get_modified_fee_rate(self, txid_or_entry) -> float:
        """Return modified fee rate in sat/vB (modified_fee / vsize).

        Used by mining selection to honour prioritisetransaction without
        re-sorting the entire by_fee_rate list on every delta change.
        Reference: Core CompareTxIterByModifiedFeeRate / DescendantScoreCompare.
        """
        if isinstance(txid_or_entry, (bytes, bytearray, memoryview)):
            txid = bytes(txid_or_entry)
            entry = self.transactions.get(txid)
            if entry is None:
                return 0.0
        else:
            entry = txid_or_entry
            txid = entry.tx.get_txid()
        modified = int(entry.fee) + int(self.map_deltas.get(txid, 0))
        size = entry.size if entry.size > 0 else 1
        return modified / size

    def clear_prioritisation(self, txid: bytes) -> None:
        """Drop *txid*'s entry from map_deltas (Core ClearPrioritisation).

        Called when a tx confirms in a block (removeForBlock clears delta —
        txmempool.cpp:420) and when a tx is removed for being conflicted with
        a new block-included tx (removeConflicts — txmempool.cpp:398).  Other
        removal reasons (REPLACED, SIZELIMIT, EXPIRY, REORG) preserve the
        delta so the tx is re-prioritised if it re-enters.
        """
        with self._lock:
            self.map_deltas.pop(txid, None)

    def get_prioritised_transactions(self) -> list[dict]:
        """Return per-tx delta info for the getprioritisedtransactions RPC.

        Mirrors Core CTxMemPool::GetPrioritisedTransactions (txmempool.cpp:673).
        Each entry: {txid: bytes, fee_delta: int, in_mempool: bool,
                     modified_fee: int|None}.
        """
        with self._lock:
            result = []
            for txid, delta in self.map_deltas.items():
                entry = self.transactions.get(txid)
                in_mempool = entry is not None
                modified_fee = (
                    int(entry.fee) + int(delta) if in_mempool else None
                )
                result.append({
                    "txid": txid,
                    "fee_delta": int(delta),
                    "in_mempool": in_mempool,
                    "modified_fee": modified_fee,
                })
            return result

    def add_transaction(self, tx: Transaction, height: int) -> tuple[bool, str]:
        """Validate and add *tx* to the mempool at *height*; returns ``(ok, error_message)``."""
        with self._lock:
            return self._add_transaction_inner(tx, height)

    def accept_to_memory_pool(
        self, tx: Transaction, height: int, test_accept: bool = False
    ) -> dict:
        """AcceptToMemoryPool - main entry point matching Bitcoin Core's AcceptToMemoryPool.

        Validates and adds a transaction to the mempool, handling RBF conflicts.

        Args:
            tx: The transaction to validate and add
            height: Current block height
            test_accept: When True, validate only without adding to mempool

        Returns:
            dict with keys: accepted (bool), txid (bytes), fee (int),
            vsize (int), reject_reason (str or None)
        """
        txid = tx.get_txid()

        if test_accept:
            # Dry-run: check if it would be accepted without modifying state.
            # Coinbase txs are never accepted into the mempool, regardless of
            # other gates — mirrors Core PreChecks (validation.cpp:802-804).
            # We use Core's definition (prev_txid is null AND prev_vout ==
            # 0xFFFFFFFF) rather than Transaction.is_coinbase to avoid false
            # positives on test fixtures that use zero-prefixed txids.
            if (
                len(tx.inputs) == 1
                and tx.inputs[0].prev_txid == bytes(32)
                and tx.inputs[0].prev_vout == 0xFFFFFFFF
            ):
                return {
                    "accepted": False, "txid": txid, "fee": 0,
                    "vsize": 0, "reject_reason": "coinbase",
                }
            with self._lock:
                # BIP-339 two-step duplicate detection (mirrors _add_transaction_inner).
                try:
                    wtxid = tx.get_wtxid()
                except Exception:
                    wtxid = txid
                if wtxid in self.wtxid_to_txid:
                    return {
                        "accepted": False, "txid": txid, "fee": 0,
                        "vsize": 0, "reject_reason": "txn-already-in-mempool",
                    }
                if txid in self.transactions:
                    return {
                        "accepted": False, "txid": txid, "fee": 0,
                        "vsize": 0, "reject_reason": "txn-same-nonwitness-data-in-mempool",
                    }
                if self.require_standard:
                    is_std, reason = _is_standard_tx(tx)
                    if not is_std:
                        return {
                            "accepted": False, "txid": txid, "fee": 0,
                            "vsize": 0, "reject_reason": f"non-standard: {reason}",
                        }
            return {
                "accepted": True, "txid": txid, "fee": 0,
                "vsize": 0, "reject_reason": None,
            }

        ok, error = self.add_transaction(tx, height)
        if ok:
            with self._lock:
                entry = self.transactions.get(txid)
            fee = int(entry.fee) if entry else 0
            vsize = entry.vsize if entry else 0
            return {
                "accepted": True, "txid": txid, "fee": fee,
                "vsize": vsize, "reject_reason": None,
            }
        else:
            return {
                "accepted": False, "txid": txid, "fee": 0,
                "vsize": 0, "reject_reason": error,
            }

    def _add_transaction_inner(self, tx: Transaction, height: int) -> tuple[bool, str]:
        """Unlocked implementation of add_transaction."""
        txid = tx.get_txid()

        # Coinbase rejection — a coinbase tx is only valid inside a block, never
        # as a loose mempool tx.  Mirrors Bitcoin Core PreChecks (validation.cpp
        # lines 802-804):
        #   if (tx.IsCoinBase())
        #       return state.Invalid(TX_CONSENSUS, "coinbase");
        # Without this gate, a malicious peer could replay block coinbases into
        # the mempool — they would not pass full consensus (no prior UTXO) but
        # could still consume CPU / orphan-pool slots before being rejected
        # downstream.
        # Core's CTransaction::IsCoinBase() (primitives/transaction.h:323):
        #   vin.size() == 1 && vin[0].prevout.IsNull()
        # where COutPoint::IsNull() = (hash.IsNull() && n == 0xFFFFFFFF).  We
        # check both prev_txid == null and prev_vout == 0xFFFFFFFF here rather
        # than relying on Transaction.is_coinbase (which only checks prev_txid;
        # see tests using zero txids that are NOT coinbases for that reason).
        if (
            len(tx.inputs) == 1
            and tx.inputs[0].prev_txid == bytes(32)
            and tx.inputs[0].prev_vout == 0xFFFFFFFF
        ):
            return False, "coinbase"

        # Check if already in mempool — BIP-339 two-step duplicate detection.
        # Core validation.cpp (PreChecks):
        #   if (m_pool.exists(GenTxid::Wtxid(wtxid)))
        #       return state.Invalid(... "txn-already-in-mempool");
        #   else if (m_pool.exists(GenTxid::Txid(txid)))
        #       return state.Invalid(... "txn-same-nonwitness-data-in-mempool");
        # The split matters: same wtxid → same tx already accepted; same txid but
        # different wtxid → a stripped/malleated variant is already in the pool.
        try:
            wtxid = tx.get_wtxid()
        except Exception:
            wtxid = txid
        if wtxid in self.wtxid_to_txid:
            return False, "txn-already-in-mempool"
        if txid in self.transactions:
            return False, "txn-same-nonwitness-data-in-mempool"

        # Already known as orphan — check by wtxid (primary key) so that
        # two malleable variants of the same txid are not conflated.
        if self.orphan_pool.has_wtxid(wtxid):
            return False, "Already in orphan pool"

        # Standardness checks (policy, not consensus)
        if self.require_standard:
            is_std, reason = _is_standard_tx(tx)
            if not is_std:
                return False, f"Non-standard transaction: {reason}"

        # Ephemeral dust: reject v3 txs with dust when submitted
        # individually (ephemeral dust is only valid inside packages).
        if tx.version == 3:
            dust_indices = _has_ephemeral_dust(tx)
            if dust_indices:
                return False, (
                    f"v3 transaction has ephemeral dust output(s) at "
                    f"index(es) {dust_indices} — must be submitted in a package"
                )

        # Check for missing parent transactions — store as orphan
        missing_parents: set[bytes] = set()
        for tx_in in tx.inputs:
            parent_txid = tx_in.prev_txid
            # Parent available if UTXO exists in chain or parent is in mempool
            utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo is None and parent_txid not in self.transactions:
                missing_parents.add(parent_txid)
        if missing_parents:
            self.orphan_pool.add(tx, missing_parents)
            return False, "orphan"

        # Build the prevScripts map once — used both by ValidateInputsStandardness
        # and IsWitnessStandard.  Resolve from chain UTXO first, then in-mempool
        # parents.  Must run after the orphan check so all prevScripts are
        # resolvable.
        if self.require_standard:
            prevscripts: dict[int, bytes] = {}
            for idx, tx_in in enumerate(tx.inputs):
                utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                if utxo is not None:
                    prevscripts[idx] = utxo["script_pubkey"]
                else:
                    parent_entry = self.transactions.get(tx_in.prev_txid)
                    if parent_entry is not None:
                        try:
                            prevscripts[idx] = parent_entry.tx.outputs[tx_in.prev_vout].script_pubkey
                        except IndexError:
                            pass  # malformed parent; consensus check will catch it

            # Input-side standardness — every prevout type must be standard
            # and P2SH redeem scripts must respect MAX_P2SH_SIGOPS.  Mirrors
            # Core's ValidateInputsStandardness (validation.cpp:897).
            iv_ok, iv_reason = _validate_inputs_standardness(tx, prevscripts)
            if not iv_ok:
                return False, iv_reason

            # IsWitnessStandard — mirrors Bitcoin Core IsWitnessStandard()
            # (policy/policy.cpp lines 265-352).  Only invoked when the tx has
            # witness data (Core: `tx.HasWitness() && require_standard`).
            if any(tx_in.witness for tx_in in tx.inputs):
                is_ws, ws_reason = _is_witness_standard(tx, prevscripts)
                if not is_ws:
                    return False, f"Non-standard transaction: {ws_reason}"

        # Per-transaction sigop cost limit (mempool policy, not consensus).
        # Reference: Bitcoin Core validation.cpp AcceptToMemoryPoolWorker:908-943
        #   nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS)
        #   if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST) → TX_NOT_STANDARD / bad-txns-too-many-sigops
        # MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 80000 / 5 = 16000
        # This is only enforced when standardness checks are active (require_standard).
        # We also save tx_sigop_cost for later use in MempoolEntry (sigop-adjusted vsize).
        # When require_standard is False, default to 0 (no sigop adjustment).
        tx_sigop_cost = 0
        if self.require_standard:
            def _utxo_resolver(prev_txid: bytes, prev_vout: int):
                utxo = self.validator.db.get_utxo(prev_txid, prev_vout)
                if utxo is not None:
                    return utxo
                parent_entry = self.transactions.get(prev_txid)
                if parent_entry is not None and prev_vout < len(parent_entry.tx.outputs):
                    out = parent_entry.tx.outputs[prev_vout]
                    return {"script_pubkey": out.script_pubkey}
                return None

            tx_sigop_cost = _compute_tx_sigop_cost(tx, _utxo_resolver)
            if tx_sigop_cost > MAX_STANDARD_TX_SIGOPS_COST:
                return False, (
                    f"bad-txns-too-many-sigops: sigop cost {tx_sigop_cost} exceeds "
                    f"MAX_STANDARD_TX_SIGOPS_COST ({MAX_STANDARD_TX_SIGOPS_COST})"
                )

        # Validate transaction (consensus + standard policy flags).
        #
        # Mempool holds txs for the NEXT block, so locktime / BIP-68 / BIP-65 /
        # BIP-112 must be evaluated at height = tip_height + 1.  Mirrors Core's
        # CheckFinalTxAtTip (validation.cpp:147-167):
        #   const int nBlockHeight = active_chain_tip.nHeight + 1;
        #   const int64_t nBlockTime = active_chain_tip.GetMedianTimePast();
        # The MTP used by BIP-113 is the *tip's* MTP (i.e. the prev block of the
        # next block), not the candidate's MTP.
        #
        # Prior to this fix the caller passed best_height (the tip height) which
        # made every nLockTime / nSequence boundary tx evaluated 1 short.
        # E.g. a tx with nLockTime == tip_height + 1 (i.e. valid in the very
        # next block) was rejected as "not final".
        next_height = height + 1
        try:
            mempool_mtp: int = self.validator.db.get_median_time_past(height) or 0
        except Exception:
            mempool_mtp = 0

        # STANDARD_SCRIPT_VERIFY_FLAGS — extra policy flags that mempool/relay
        # enforces beyond the per-height consensus flags.  Mirrors Core's
        # PolicyScriptChecks (validation.cpp:1135-1156) which calls
        # CheckInputScripts with STANDARD_SCRIPT_VERIFY_FLAGS.  Block validation
        # uses only the consensus flags via CheckInputScripts in ConnectBlock.
        # Computed as the standard-set minus the consensus-set so we only OR in
        # the policy-only delta (NULLFAIL, LOW_S, CLEANSTACK, SIGPUSHONLY,
        # MINIMALDATA, MINIMALIF, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE,
        # DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        # DISCOURAGE_OP_SUCCESS).
        extra_flags = 0
        if self.require_standard:
            try:
                from ouroboros.script import (
                    get_flags_for_height as _consensus_flags,
                    get_standard_script_flags as _standard_flags,
                )
                consensus = _consensus_flags(next_height, None, self.validator.network if hasattr(self.validator, "network") else "mainnet")
                standard = _standard_flags(next_height, None, self.validator.network if hasattr(self.validator, "network") else "mainnet")
                # Bitmask delta — only the standard-only bits.
                extra_flags = (standard & ~consensus)
            except Exception:
                # Test doubles may not implement the script module; fall back
                # to consensus-only verification (current behavior).
                extra_flags = 0

        try:
            valid, error = self.validator.validate_transaction(
                tx, next_height, mempool_mtp, extra_script_flags=extra_flags,
            )
        except TypeError:
            # Older test doubles do not implement the extra_script_flags
            # parameter — fall back through progressively simpler signatures.
            try:
                valid, error = self.validator.validate_transaction(
                    tx, next_height, mempool_mtp,
                )
            except TypeError:
                valid, error = self.validator.validate_transaction(
                    tx, next_height,
                )
        if not valid:
            return False, error

        # Check for conflicts (double spends) — attempt BIP 125 RBF
        has_conflict = any(
            (tx_in.prev_txid, tx_in.prev_vout) in self.spent_outputs
            for tx_in in tx.inputs
        )
        if has_conflict:
            return self.try_replace(tx, height)

        # TRUC (v3 transaction) policy checks — must come before general
        # ancestor/descendant limits. This handles both v3 and non-v3 txs
        # (non-v3 txs are checked for spending from v3 parents).
        # Pass the already-computed sigop_cost so the vsize used for TRUC limits
        # matches Bitcoin Core's sigop-adjusted GetVirtualTransactionSize().
        # Also build a direct_conflicts set (empty here since we handle the
        # conflict path above via try_replace) to match Core's SingleTRUCChecks
        # signature which uses it to avoid double-counting a sibling that is
        # already going to be replaced by the incoming RBF tx.
        # Reference: bitcoin-core/src/policy/truc_policy.cpp:171-261
        truc_ok, truc_err, sibling_txid = self._check_truc_policy(
            tx, sigop_cost=tx_sigop_cost, direct_conflicts=set()
        )
        if not truc_ok:
            if sibling_txid is not None:
                # Sibling eviction: try to replace the existing child
                return self._try_sibling_eviction(tx, sibling_txid, height)
            return False, truc_err

        # Ancestor/descendant limits (Bitcoin Core: CalculateMemPoolAncestors)
        ancestors = self._get_ancestors(tx)
        # Stripped non-witness byte count: used for raw byte-budget accounting
        # (mempool max_size, ancestor_size, descendant_size stored on entries).
        # These track actual RAM / disk byte consumption, not fee-rate vsize.
        tx_size = len(tx.serialize())
        # tx_sigop_cost was computed above (in the require_standard block); it is
        # 0 when standardness checks are disabled.  Derive the sigop-adjusted
        # vsize for fee-rate and relay-fee checks, matching Core:
        #   ws.m_vsize = ws.m_tx_handle->GetTxSize()
        #              = GetVirtualTransactionSize(weight, sigOpCost, nBytesPerSigOp)
        # Reference: bitcoin-core/src/validation.cpp:932,
        #            bitcoin-core/src/kernel/mempool_entry.h:110-113
        tx_vsize = get_virtual_transaction_size(tx.get_weight(), tx_sigop_cost, DEFAULT_BYTES_PER_SIGOP)

        # Check ancestor count limit
        if len(ancestors) + 1 > MAX_ANCESTOR_COUNT:
            return False, (
                f"Too many ancestors: {len(ancestors) + 1} > {MAX_ANCESTOR_COUNT}")

        # Check ancestor size limit (101KB)
        ancestor_size = sum(self.transactions[a].size for a in ancestors if a in self.transactions)
        if ancestor_size + tx_size > MAX_ANCESTOR_SIZE_KVB * 1000:
            return False, (
                f"Ancestor size limit exceeded: {ancestor_size + tx_size} > "
                f"{MAX_ANCESTOR_SIZE_KVB * 1000}")

        # Check descendant limits for each ancestor
        for a_txid in ancestors:
            if a_txid in self.transactions:
                entry = self.transactions[a_txid]
                # Descendant count limit
                if entry.descendant_count + 1 > MAX_DESCENDANT_COUNT:
                    return False, (
                        f"Too many descendants for ancestor {a_txid.hex()[:16]}...: "
                        f"{entry.descendant_count + 1} > {MAX_DESCENDANT_COUNT}")
                # Descendant size limit (101KB)
                if entry.descendant_size + tx_size > MAX_DESCENDANT_SIZE_KVB * 1000:
                    return False, (
                        f"Descendant size limit exceeded for {a_txid.hex()[:16]}...: "
                        f"{entry.descendant_size + tx_size} > {MAX_DESCENDANT_SIZE_KVB * 1000}")

        # Check cluster size limit
        cluster_ok, cluster_err = self._check_cluster_limit(tx)
        if not cluster_ok:
            return False, cluster_err

        # Check mempool size
        if self.current_size + tx_size > self.max_size:
            self._evict_low_fee_txs(tx_size)

        # Calculate fee
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo:
                total_input += utxo['value']
            else:
                return False, f"UTXO not found: {tx_in.prev_txid.hex()[:16]}...:{tx_in.prev_vout}"

        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output

        if fee < 0:
            return False, "Negative fee"

        # PreCheckEphemeralTx — a non-zero-fee transaction may not have dust
        # outputs (the dust output must be CPFP'd by a child in a package).
        # Mirrors Bitcoin Core PreCheckEphemeralTx (policy/ephemeral_policy.cpp:23-31)
        # which is called from PreChecks at validation.cpp:935-938.  Core gates
        # this on require_standard; we match that.  Note that this is in addition
        # to the IsStandardTx gate that already enforces MAX_DUST_OUTPUTS_PER_TX
        # (≤ 1 dust output).  v3 txs with dust have already been rejected above.
        if self.require_standard and fee != 0:
            dust_indices = _has_ephemeral_dust(tx)
            if dust_indices:
                return False, (
                    f"dust: tx with dust output at index(es) {dust_indices} "
                    f"must be 0-fee (got {fee} sat)"
                )

        # fee_rate uses the sigop-adjusted vsize, matching Core's CFeeRate which
        # calls GetTxSize() = GetVirtualTransactionSize(weight, sigopCost, nBytesPerSigOp).
        # Reference: bitcoin-core/src/validation.cpp:993
        #   CFeeRate newFeeRate(ws.m_modified_fees, ws.m_vsize);
        fee_rate = fee / tx_vsize if tx_vsize > 0 else 0

        # Minimum relay fee check uses vsize (same source as fee_rate).
        # DEFAULT_MIN_RELAY_TX_FEE is in sat/kB; convert to sat for this tx.
        min_relay = (tx_vsize * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        if fee < min_relay:
            return False, f"Below minimum relay fee: {fee} < {min_relay}"

        # Rolling minimum fee check (txmempool.cpp GetMinFee gate).
        # After TrimToSize evicts transactions the rolling min fee rises so
        # that evicted txs cannot immediately re-enter.  Core checks:
        #   if (pool.GetMinFee().GetFeePerK() > minRelayTxFee.GetFeePerK())
        #       if (ws.m_modified_fees < pool.GetMinFee().GetFee(ws.m_vsize))
        #           return state.Invalid(...)
        # Reference: validation.cpp AcceptToMemoryPoolWorker (fee-filter gate).
        rolling_min_kvb = self._get_min_fee_inner()  # sat/kvB
        if rolling_min_kvb > DEFAULT_MIN_RELAY_TX_FEE:
            rolling_min_fee = (tx_vsize * rolling_min_kvb) // 1000
            if fee < rolling_min_fee:
                return False, (
                    f"Insufficient fee: {fee} sat < rolling minimum "
                    f"{rolling_min_fee} sat (min rate {rolling_min_kvb:.1f} sat/kvB)"
                )

        # Compute direct parents (mempool txs this tx spends from)
        direct_parents: set[bytes] = set()
        for tx_in in tx.inputs:
            if tx_in.prev_txid in self.transactions:
                direct_parents.add(tx_in.prev_txid)

        # Add to mempool
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee_rate,
            size=tx_size,
            time_added=time.time(),
            height_added=height,
            sigop_cost=tx_sigop_cost,
            ancestor_count=len(ancestors) + 1,
            ancestor_size=ancestor_size + tx_size,
            parents=direct_parents,
            children=set(),
        )

        self.transactions[txid] = entry
        # BIP 152 / BIP 339 dual index — register wtxid → txid.  For non-
        # segwit txs wtxid == txid and the entry is overwritten harmlessly.
        try:
            wtxid = tx.get_wtxid()
        except Exception:
            wtxid = txid
        self.wtxid_to_txid[wtxid] = txid
        self.current_size += tx_size

        # Track spent outputs
        for tx_in in tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            self.spent_outputs.add(outpoint)

        # Update parent entries to add this txid as a child
        for parent_txid in direct_parents:
            if parent_txid in self.transactions:
                self.transactions[parent_txid].children.add(txid)

        # Update ancestor descendant counts
        for a_txid in ancestors:
            if a_txid in self.transactions:
                self.transactions[a_txid].descendant_count += 1
                self.transactions[a_txid].descendant_size += tx_size

        # Insert sorted by fee rate
        self._insert_sorted_by_fee_rate(txid, fee_rate)

        # Update cluster manager
        self._cluster_manager.add_transaction(txid)

        # Get sequence number for this add event
        seq = self._next_sequence()

        logger.info(
            f"Added transaction {txid.hex()[:16]}... to mempool "
            f"(fee: {fee}, rate: {fee_rate:.2f} sat/vbyte, seq: {seq})"
        )

        # Emit notification callback for ZMQ sequence topic
        if self._on_tx_added is not None:
            try:
                self._on_tx_added(txid, tx, seq)
            except Exception as e:
                logger.warning(f"on_tx_added callback error: {e}")

        # Try to resolve orphans that were waiting on this transaction
        self._resolve_orphans(txid, height)

        return True, ""

    def _get_ancestors(self, tx: Transaction) -> set[bytes]:
        """Get all ancestors (transitive parents) of a transaction.

        Uses parent links stored on MempoolEntry for efficient traversal.
        For a tx not yet in the mempool, computes direct parents from inputs.
        """
        result: set[bytes] = set()
        queue: list[bytes] = []

        # Find direct parents from inputs
        for inp in tx.inputs:
            if inp.prev_txid in self.transactions:
                queue.append(inp.prev_txid)
                result.add(inp.prev_txid)

        # BFS through parent links
        while queue:
            parent_txid = queue.pop()
            parent_entry = self.transactions.get(parent_txid)
            if parent_entry is None:
                continue
            # Use stored parent links for efficient traversal
            for grandparent_txid in parent_entry.parents:
                if grandparent_txid not in result and grandparent_txid in self.transactions:
                    result.add(grandparent_txid)
                    queue.append(grandparent_txid)
        return result

    def _check_cluster_limit(self, tx: Transaction) -> tuple[bool, str]:
        """Check if adding a transaction would exceed cluster limits.

        Bitcoin Core enforces two independent cluster limits
        (kernel/mempool_limits.h MemPoolLimits / txmempool.cpp:179-181):
          1. cluster_count  <= DEFAULT_CLUSTER_LIMIT = 64 transactions
          2. cluster_size   <= DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000 vbytes

        Both are checked before admitting a new transaction.  A single
        transaction that would merge several existing clusters is evaluated
        against the *merged* total.

        Reference: Bitcoin Core txmempool.cpp:179-181, policy/policy.h:72-74,
                   kernel/mempool_limits.h
        """
        # Determine the vsize of the incoming tx (virtual bytes = ceil(weight/4))
        tx_vsize = tx.get_vsize() if hasattr(tx, "get_vsize") else len(tx.serialize())

        # Find all clusters that would be merged by this transaction
        neighbor_cluster_ids: set[int] = set()
        for inp in tx.inputs:
            cid = self._cluster_manager.get_cluster_id(inp.prev_txid)
            if cid is not None:
                neighbor_cluster_ids.add(cid)

        if not neighbor_cluster_ids:
            # New singleton cluster — always OK for count/size gates
            return True, ""

        # Gate 1: count — total transactions in the merged cluster
        total_count = 1  # the new transaction itself
        for cid in neighbor_cluster_ids:
            cluster = self._cluster_manager._clusters.get(cid)
            if cluster:
                total_count += cluster.size()

        if total_count > MAX_CLUSTER_COUNT:
            return False, (
                f"Transaction would create cluster of {total_count} txs "
                f"exceeding limit {MAX_CLUSTER_COUNT} "
                f"(policy/policy.h DEFAULT_CLUSTER_LIMIT)"
            )

        # Gate 2: vbyte size — total virtual bytes in the merged cluster
        # Sum the stored .size field for each txid across all neighbor clusters.
        total_vbytes = tx_vsize
        for cid in neighbor_cluster_ids:
            cluster = self._cluster_manager._clusters.get(cid)
            if cluster:
                for txid in cluster.txids:
                    entry = self._cluster_manager.transactions.get(txid)
                    if entry is not None:
                        total_vbytes += entry.size

        if total_vbytes > MAX_CLUSTER_SIZE_VBYTES:
            return False, (
                f"Transaction would create cluster of {total_vbytes} vbytes "
                f"exceeding limit {MAX_CLUSTER_SIZE_VBYTES} "
                f"(policy/policy.h DEFAULT_CLUSTER_SIZE_LIMIT_KVB)"
            )

        return True, ""

    # --- TRUC (v3) helpers ---

    def _is_truc(self, tx: Transaction) -> bool:
        """Check if a transaction is a TRUC (v3) transaction."""
        return tx.version == TRUC_VERSION

    def _check_truc_policy(
        self,
        tx: Transaction,
        sigop_cost: int = 0,
        direct_conflicts: set[bytes] | None = None,
    ) -> tuple[bool, str, bytes | None]:
        """Enforce TRUC policy for a transaction being added.

        This implements Bitcoin Core's SingleTRUCChecks (policy/truc_policy.cpp).

        Args:
            tx: The transaction being submitted.
            sigop_cost: The BIP-141-weighted sigop cost of tx (from
                _compute_tx_sigop_cost).  Used to compute the sigop-adjusted
                virtual size that Core uses for all TRUC size limits.
                Reference: truc_policy.cpp:200, kernel/mempool_entry.h:110-113.
            direct_conflicts: Set of in-mempool txids that this tx conflicts
                with (i.e., transactions that share at least one input with
                tx).  Used to avoid double-counting a sibling that is already
                going to be replaced via RBF.
                Reference: truc_policy.cpp:240-242.

        Returns:
            (ok, error_message, sibling_txid)
            - ok: True if the transaction passes all TRUC checks
            - error_message: Error description if ok is False
            - sibling_txid: If a v3 parent already has a child that can be
                           considered for sibling eviction, returns that
                           child's txid. None otherwise.
        """
        if direct_conflicts is None:
            direct_conflicts = set()

        # Sigop-adjusted virtual size — matches Core's SingleTRUCChecks int64_t vsize
        # parameter which is pre-computed via GetVirtualTransactionSize(weight, sigop_cost).
        # Reference: validation.cpp passes sigop_cost into SingleTRUCChecks.
        tx_vsize = get_virtual_transaction_size(
            tx.get_weight(), sigop_cost, DEFAULT_BYTES_PER_SIGOP
        )

        # Gate 1+2: TRUC/non-TRUC inheritance (both v3 and non-v3 txs).
        # A v3 tx must only have v3 unconfirmed ancestors; a non-v3 tx must
        # only have non-v3 unconfirmed ancestors.
        # Reference: truc_policy.cpp:178-191
        tx_is_v3 = self._is_truc(tx)
        for inp in tx.inputs:
            parent_entry = self.transactions.get(inp.prev_txid)
            if parent_entry is None:
                continue  # confirmed parent — no inheritance constraint

            parent_is_v3 = self._is_truc(parent_entry.tx)

            if tx_is_v3 and not parent_is_v3:
                return False, (
                    f"version=3 tx cannot spend from non-version=3 tx "
                    f"{inp.prev_txid.hex()}"
                ), None

            if not tx_is_v3 and parent_is_v3:
                return False, (
                    f"non-version=3 tx cannot spend from version=3 tx "
                    f"{inp.prev_txid.hex()}"
                ), None

        # Remaining gates only apply to v3 transactions.
        # Reference: truc_policy.cpp:198
        if not tx_is_v3:
            return True, "", None

        # Gate 3: TRUC_MAX_VSIZE — any v3 tx must be <= 10,000 vbytes.
        # Core uses sigop-adjusted vsize here.
        # Reference: truc_policy.cpp:200-204
        if tx_vsize > TRUC_MAX_VSIZE:
            return False, (
                f"version=3 tx is too big: {tx_vsize} > {TRUC_MAX_VSIZE} virtual bytes"
            ), None

        # Gate 4: ancestor count limit — v3 tx may have at most 1 unconfirmed
        # ancestor (TRUC_ANCESTOR_LIMIT=2 includes self).
        # Reference: truc_policy.cpp:207-211
        ancestors = self._get_ancestors(tx)
        if len(ancestors) + 1 > TRUC_ANCESTOR_LIMIT:
            return False, "tx would have too many ancestors", None

        # Gates 5/6 only apply when there is at least one unconfirmed parent.
        if not ancestors:
            return True, "", None

        # Extract the single unconfirmed parent (TRUC allows exactly one).
        # We pick the first one via the ancestor set since the ancestor-limit
        # check above guarantees there is exactly 1.
        parent_entry = None
        for inp in tx.inputs:
            pe = self.transactions.get(inp.prev_txid)
            if pe is not None:
                parent_entry = pe
                break
        if parent_entry is None:
            # Ancestors set is non-empty but no direct parent found — shouldn't happen.
            return True, "", None

        # Gate 4b: the in-mempool parent itself must not already have an
        # unconfirmed ancestor (that would put tx's ancestor count at 3).
        # Core: pool.GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT
        # Reference: truc_policy.cpp:217-220
        if parent_entry.ancestor_count + 1 > TRUC_ANCESTOR_LIMIT:
            return False, "tx would have too many ancestors", None

        # Gate 5: TRUC_CHILD_MAX_VSIZE — a v3 child of an unconfirmed v3
        # parent must be <= 1,000 vbytes (sigop-adjusted).
        # Reference: truc_policy.cpp:223-227
        if tx_vsize > TRUC_CHILD_MAX_VSIZE:
            return False, (
                f"version=3 child tx is too big: {tx_vsize} > "
                f"{TRUC_CHILD_MAX_VSIZE} virtual bytes"
            ), None

        # Gate 6: descendant count limit — the parent may have at most 1
        # unconfirmed child.  Core: pool.GetDescendantCount(parent)+1 > LIMIT.
        # We use parent_entry.children (always up-to-date, even during sibling
        # eviction where _skip_recount=True leaves descendant_count stale)
        # rather than parent_entry.descendant_count for the primary gate.
        # Reference: truc_policy.cpp:243-258
        existing_children = list(parent_entry.children)
        if existing_children:
            # The parent already has a child. Check whether that child is
            # going to be replaced by a direct conflict (RBF) — if so, we
            # don't need sibling eviction.
            # Reference: truc_policy.cpp:240-242 (child_will_be_replaced)
            child_will_be_replaced = bool(
                direct_conflicts.intersection(existing_children)
            )
            if child_will_be_replaced:
                # The sibling conflict will be resolved by RBF; no limit violation.
                return True, "", None

            # Consider sibling eviction when the parent has exactly 1 child
            # and that child has no descendants of its own (i.e., it is a
            # simple 1-parent-1-child cluster).
            # Core: consider_sibling_eviction =
            #   GetDescendantCount(parent) == 2 && GetAncestorCount(sibling) == 2
            # GetDescendantCount(parent)==2 means parent has exactly 1 child; we
            # additionally verify via descendant_count (which may be stale during
            # sibling eviction, but we have the children set as the source of truth).
            # Reference: truc_policy.cpp:249-250
            parent_desc_count = parent_entry.descendant_count  # includes self
            consider_sibling_eviction = (
                len(existing_children) == 1
                and parent_desc_count == 2
            )
            if consider_sibling_eviction:
                sibling_txid = existing_children[0]
                sibling_entry = self.transactions.get(sibling_txid)
                # Sibling must itself have exactly 1 ancestor (parent only) for
                # the simple topology Core requires.
                if sibling_entry and sibling_entry.ancestor_count == 2:
                    return False, "tx would exceed descendant count limit", sibling_txid

            return False, "tx would exceed descendant count limit", None

        return True, "", None

    def _check_package_truc_policy(
        self, txs: list[Transaction]
    ) -> tuple[bool, str]:
        """Check TRUC policy for a package of transactions.

        This implements Bitcoin Core's PackageTRUCChecks (policy/truc_policy.cpp).

        For each transaction in the package:
        - If TRUC: verify parents (in mempool or package) are also TRUC
        - If non-TRUC: verify no TRUC parents (in mempool or package)
        - Check ancestor/descendant limits considering both mempool and package
        - Check child vsize limits (sigop-adjusted, matching Core)

        Args:
            txs: List of transactions in topological order

        Returns:
            (ok, error_message)
        """
        # Build lookup for package txids and their versions
        package_txids = {tx.get_txid(): tx for tx in txs}

        # Build a UTXO resolver that can look up script_pubkeys for sigop
        # counting: checks package outputs first (topological), then mempool
        # parents, then the chain UTXO set.
        # We build package_outputs as we iterate in topological order below.
        package_script_pubkeys: dict[tuple[bytes, int], bytes] = {}

        for tx in txs:
            txid = tx.get_txid()
            tx_is_v3 = self._is_truc(tx)

            # Compute sigop-adjusted vsize for this tx.
            # Core's PackageTRUCChecks receives pre-computed vsize per tx
            # (validation.cpp passes it in); we compute it here inline.
            # Reference: truc_policy.cpp:71-73 (vsize already checked by
            # SingleTRUCChecks before PackageTRUCChecks is called), but
            # PackageTRUCChecks re-checks to be safe.
            def _pkg_utxo_resolver(prev_txid: bytes, prev_vout: int):
                key = (prev_txid, prev_vout)
                spk = package_script_pubkeys.get(key)
                if spk is not None:
                    return {"script_pubkey": spk}
                mp_entry = self.transactions.get(prev_txid)
                if mp_entry is not None and prev_vout < len(mp_entry.tx.outputs):
                    return {"script_pubkey": mp_entry.tx.outputs[prev_vout].script_pubkey}
                utxo = self.validator.db.get_utxo(prev_txid, prev_vout)
                return utxo

            tx_sigop_cost = _compute_tx_sigop_cost(tx, _pkg_utxo_resolver)
            tx_vsize = get_virtual_transaction_size(
                tx.get_weight(), tx_sigop_cost, DEFAULT_BYTES_PER_SIGOP
            )

            # Register this tx's outputs for children later in the package.
            for vout, out in enumerate(tx.outputs):
                package_script_pubkeys[(txid, vout)] = out.script_pubkey

            # Collect in-mempool and in-package parents (use sets to avoid
            # double-counting when multiple inputs spend from the same parent)
            mempool_parents: set[bytes] = set()
            package_parents: set[bytes] = set()

            for inp in tx.inputs:
                if inp.prev_txid in self.transactions:
                    mempool_parents.add(inp.prev_txid)
                elif inp.prev_txid in package_txids and inp.prev_txid != txid:
                    package_parents.add(inp.prev_txid)

            if tx_is_v3:
                # Gate: TRUC_MAX_VSIZE for any v3 tx.
                # Reference: truc_policy.cpp:71-73 (SingleTRUCChecks should have
                # caught this; PackageTRUCChecks re-validates as a safety net).
                if tx_vsize > TRUC_MAX_VSIZE:
                    return False, (
                        f"version=3 tx {txid.hex()} is too big: "
                        f"{tx_vsize} > {TRUC_MAX_VSIZE} virtual bytes"
                    )

                # Gate: ancestor count (mempool_parents + package_parents + self).
                # Reference: truc_policy.cpp:76-79
                total_ancestors = len(mempool_parents) + len(package_parents)
                if total_ancestors + 1 > TRUC_ANCESTOR_LIMIT:
                    return False, f"tx {txid.hex()} would have too many ancestors"

                # Gate: if a mempool parent exists, its own ancestor count must
                # also leave room.
                # Reference: truc_policy.cpp:81-85
                for mp_txid in mempool_parents:
                    mp_entry = self.transactions.get(mp_txid)
                    if mp_entry:
                        # mp_entry.ancestor_count includes the parent itself.
                        # Adding in_package_parents and the child (1) must
                        # not exceed the limit.
                        if mp_entry.ancestor_count + len(package_parents) + 1 > TRUC_ANCESTOR_LIMIT:
                            return False, f"tx {txid.hex()} would have too many ancestors"

                has_parent = total_ancestors > 0
                if has_parent:
                    # Gate: TRUC_CHILD_MAX_VSIZE for a v3 child with an
                    # unconfirmed parent (sigop-adjusted).
                    # Reference: truc_policy.cpp:91-95
                    if tx_vsize > TRUC_CHILD_MAX_VSIZE:
                        return False, (
                            f"version=3 child tx {txid.hex()} is too big: "
                            f"{tx_vsize} > {TRUC_CHILD_MAX_VSIZE} virtual bytes"
                        )

                    # Identify the single parent (exactly 1 per ancestor-limit check).
                    # Core picks the mempool parent first, then the package parent.
                    # Reference: truc_policy.cpp:98-113
                    if mempool_parents:
                        parent_txid = next(iter(mempool_parents))
                        parent_tx: Transaction | None = self.transactions[parent_txid].tx
                    else:
                        parent_txid = next(iter(package_parents))
                        parent_tx = package_txids.get(parent_txid)

                    # Gate: parent must be TRUC.
                    # Reference: truc_policy.cpp:116-119
                    if parent_tx is not None and not self._is_truc(parent_tx):
                        return False, (
                            f"version=3 tx {txid.hex()} cannot spend from "
                            f"non-version=3 tx {parent_txid.hex()}"
                        )

                    # Gate: no sibling allowed — no other tx in the package
                    # may spend from the same parent.
                    # Reference: truc_policy.cpp:122-134
                    for other_tx in txs:
                        other_txid = other_tx.get_txid()
                        if other_txid == txid:
                            continue
                        for inp in other_tx.inputs:
                            if inp.prev_txid == parent_txid:
                                return False, (
                                    f"tx {parent_txid.hex()} would exceed "
                                    f"descendant count limit"
                                )
                            # Gate: this tx cannot itself be a parent of another
                            # tx in the package (no grandchild in package).
                            # Reference: truc_policy.cpp:136-139
                            if inp.prev_txid == txid:
                                return False, (
                                    f"tx {other_txid.hex()} would have too many ancestors"
                                )

                    # Gate: the mempool parent must not already have a descendant
                    # (other than itself), since that would push it to 3.
                    # Reference: truc_policy.cpp:144-147
                    if mempool_parents:
                        mp_txid = next(iter(mempool_parents))
                        mp_entry = self.transactions.get(mp_txid)
                        if mp_entry and mp_entry.descendant_count > 1:
                            return False, (
                                f"tx {mp_txid.hex()} would exceed descendant count limit"
                            )

            else:
                # Non-v3 tx cannot have v3 parents (in mempool or package).
                # Reference: truc_policy.cpp:150-167
                for mp_txid in mempool_parents:
                    mp_entry = self.transactions.get(mp_txid)
                    if mp_entry and self._is_truc(mp_entry.tx):
                        return False, (
                            f"non-version=3 tx {txid.hex()} cannot spend from "
                            f"version=3 tx {mp_txid.hex()}"
                        )
                for pp_txid in package_parents:
                    pp_tx = package_txids.get(pp_txid)
                    if pp_tx and self._is_truc(pp_tx):
                        return False, (
                            f"non-version=3 tx {txid.hex()} cannot spend from "
                            f"version=3 tx {pp_txid.hex()}"
                        )

        return True, ""

    def _get_v3_children(self, parent_txid: bytes) -> list[bytes]:
        """Get direct children of a transaction in the mempool."""
        parent_entry = self.transactions.get(parent_txid)
        if parent_entry is None:
            return []
        return list(parent_entry.children)

    def _try_sibling_eviction(
        self, new_tx: Transaction, sibling_txid: bytes, height: int
    ) -> tuple[bool, str]:
        """Attempt TRUC sibling eviction.

        When a TRUC parent already has one child, a new child can replace
        the existing sibling if it pays a higher fee rate. This is a special
        form of RBF specific to TRUC transactions.

        Reference: Bitcoin Core policy/truc_policy.cpp (sibling eviction logic)
        """
        sibling_entry = self.transactions.get(sibling_txid)
        if sibling_entry is None:
            return False, "Sibling transaction not found"

        # Calculate new tx fee
        new_size = len(new_tx.serialize())
        total_input = 0
        for inp in new_tx.inputs:
            utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo:
                total_input += utxo['value']
            else:
                # Check mempool parent output
                parent_entry = self.transactions.get(inp.prev_txid)
                if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                    total_input += parent_entry.tx.outputs[inp.prev_vout].value
                else:
                    return False, f"UTXO not found: {inp.prev_txid.hex()[:16]}...:{inp.prev_vout}"

        total_output = sum(out.value for out in new_tx.outputs)
        new_fee = total_input - total_output

        if new_fee < 0:
            return False, "Negative fee"

        # Sibling eviction requires:
        # 1. New fee > sibling fee (strictly higher)
        # 2. New fee covers incremental relay fee for new tx size
        sibling_fee = sibling_entry.fee

        if new_fee <= sibling_fee:
            return False, (
                f"Sibling eviction requires higher fee: {new_fee} <= {sibling_fee}"
            )

        # Check incremental relay fee
        incremental_fee_needed = (new_size * self.INCREMENTAL_RELAY_FEE) // 1000
        additional_fee = new_fee - sibling_fee
        if additional_fee < incremental_fee_needed:
            return False, (
                f"Sibling eviction does not cover incremental relay fee: "
                f"additional {additional_fee} < required {incremental_fee_needed}"
            )

        # All checks passed - evict sibling and add new tx
        logger.info(
            f"TRUC sibling eviction: replacing {sibling_txid.hex()[:16]}... "
            f"with {new_tx.get_txid().hex()[:16]}..."
        )

        # Remove sibling
        self.remove_transaction(sibling_txid, _skip_recount=True, _reason="sibling-evicted")

        # Now add the new transaction (it should pass all checks)
        # We need to be careful to avoid infinite recursion - the sibling
        # is already removed so the parent no longer has a child.
        ok, err = self._add_transaction_inner(new_tx, height)
        if not ok:
            # This shouldn't happen if our checks are correct
            logger.warning(f"Failed to add tx after sibling eviction: {err}")
            return False, f"Failed after sibling eviction: {err}"

        return True, ""

    def _recalculate_ancestors(self, txid: bytes) -> None:
        entry = self.transactions.get(txid)
        if entry is None:
            return
        ancestors = self._get_ancestors(entry.tx)
        entry.ancestor_count = len(ancestors) + 1
        entry.ancestor_size = (
            sum(self.transactions[a].size for a in ancestors if a in self.transactions)
            + entry.size
        )

    def _update_descendants_after_removal(
        self,
        removed_txid: bytes,
        former_children: set[bytes] | None = None,
        former_parents: set[bytes] | None = None,
    ) -> None:
        """After removing *removed_txid*, fix ancestor/descendant counts.

        Args:
            removed_txid: The txid that was just removed.
            former_children: The children set of the removed entry (if available).
            former_parents: The parents set of the removed entry (if available).
                Required to correctly decrement ancestor descendant_count when
                removing a leaf (no children).  Without it, affected_ancestors
                is populated only from children — which is empty for leaves —
                so the parent's descendant_count is never decremented (W106 G6).
        """
        # Find direct children of removed tx. Use former_children if provided,
        # otherwise scan transactions (slower fallback for compatibility).
        if former_children is not None:
            children = former_children
        else:
            children = set()
            for child_txid, child_entry in self.transactions.items():
                for inp in child_entry.tx.inputs:
                    if inp.prev_txid == removed_txid:
                        children.add(child_txid)
                        break

        # Collect all descendants of removed tx (via children) using children links
        all_desc: set[bytes] = set()
        queue = list(children)
        while queue:
            t = queue.pop()
            if t in all_desc:
                continue
            all_desc.add(t)
            # Use children links for efficient traversal
            entry = self.transactions.get(t)
            if entry:
                for child_txid in entry.children:
                    if child_txid not in all_desc and child_txid in self.transactions:
                        queue.append(child_txid)

        # Recalculate ancestor counts for all affected descendants
        for desc_txid in all_desc:
            self._recalculate_ancestors(desc_txid)
            # Also update the parents set (remove removed_txid if present)
            desc_entry = self.transactions.get(desc_txid)
            if desc_entry:
                desc_entry.parents.discard(removed_txid)

        # Rebuild descendant counts for ancestors of the direct children.
        # These ancestors lost removed_txid (and possibly its descendants) from
        # their descendant sets.
        affected_ancestors: set[bytes] = set()
        for child_txid in children:
            child_entry = self.transactions.get(child_txid)
            if child_entry:
                affected_ancestors |= self._get_ancestors(child_entry.tx)

        # BUG-G6 fix: when removed_txid was a leaf (no children), the loop
        # above never runs and affected_ancestors stays empty, so the parent's
        # descendant_count is never decremented.  Seed affected_ancestors with
        # the direct parents of the removed tx (and their transitive ancestors)
        # so their descendant counts are always recalculated.
        if former_parents:
            for par_txid in former_parents:
                if par_txid in self.transactions:
                    affected_ancestors.add(par_txid)
                    par_entry = self.transactions[par_txid]
                    affected_ancestors |= self._get_ancestors(par_entry.tx)

        for anc_txid in affected_ancestors:
            if anc_txid in self.transactions:
                descs = self._collect_descendants(anc_txid)
                descs.discard(anc_txid)  # don't count self
                anc_entry = self.transactions[anc_txid]
                anc_entry.descendant_count = len(descs) + 1  # +1 for self
                anc_entry.descendant_size = (
                    anc_entry.size
                    + sum(
                        self.transactions[d].size
                        for d in descs
                        if d in self.transactions
                    )
                )

    def _resolve_orphans(self, parent_txid: bytes, height: int) -> int:
        accepted = 0
        work_queue = [parent_txid]

        while work_queue:
            ptxid = work_queue.pop(0)
            candidates = self.orphan_pool.get_orphans_for_parent(ptxid)
            for orphan_tx in candidates:
                orphan_wtxid = orphan_tx.get_wtxid()
                orphan_txid = orphan_tx.get_txid()
                # Remove from orphan pool first (by wtxid, primary key) so
                # add_transaction doesn't see it as "already in orphan pool"
                self.orphan_pool.remove(orphan_wtxid)
                ok, err = self.add_transaction(orphan_tx, height)
                if ok:
                    accepted += 1
                    # This newly-accepted tx may unblock more orphans;
                    # queue by txid since by_parent is indexed by txid
                    work_queue.append(orphan_txid)
                    logger.info(
                        f"Resolved orphan wtxid={orphan_wtxid.hex()[:16]}... "
                        f"txid={orphan_txid.hex()[:16]}... "
                        f"(parent {ptxid.hex()[:16]}...)"
                    )
                # If it fails for a non-orphan reason, it stays removed

        return accepted

    def expire_old_transactions(self, current_time: float | None = None) -> int:
        """Remove transactions that have been in the mempool too long."""
        with self._lock:
            return self._expire_old_transactions_inner(current_time)

    def _expire_old_transactions_inner(self, current_time: float | None = None) -> int:
        now = current_time or time.time()
        cutoff = now - (MEMPOOL_EXPIRY_HOURS * 3600)

        # Collect directly-expired transactions (those added before cutoff).
        directly_expired = [
            txid for txid, entry in self.transactions.items()
            if entry.time_added < cutoff
        ]

        # Expand to full descendant closure — mirrors Bitcoin Core Expire()
        # which calls CalculateDescendants on each expired entry before removal
        # (txmempool.cpp:822-825).  Without this, a child of an expired parent
        # would be left orphaned in the pool with a dangling input pointer.
        stage: set[bytes] = set()
        for txid in directly_expired:
            stage |= self._collect_descendants(txid)

        for txid in list(stage):
            self._remove_transaction_inner(txid, _reason="expiry")

        removed_count = len(stage)
        if removed_count > 0:
            logger.info(
                f"Expired {removed_count} mempool transactions "
                f"({len(directly_expired)} direct + {removed_count - len(directly_expired)} descendants)"
            )

        # Also expire old orphans
        self.orphan_pool.expire()

        return removed_count

    def remove_transaction(
        self,
        txid: bytes,
        _skip_recount: bool = False,
        _reason: str = "unknown",
    ):
        """
        Remove transaction from mempool.

        Args:
            txid: Transaction ID to remove
            _skip_recount: Internal flag — skip ancestor/descendant
                recalculation (used during batch removals that do a
                single recalculation pass afterward).
            _reason: Reason for removal (for notification callback)
        """
        with self._lock:
            self._remove_transaction_inner(txid, _skip_recount, _reason)

    def _remove_transaction_inner(
        self, txid: bytes, _skip_recount: bool = False, _reason: str = "unknown"
    ):
        if txid not in self.transactions:
            return

        entry = self.transactions[txid]
        self.current_size -= entry.size

        # Save children and parents for recounting (before we modify links)
        former_children = set(entry.children)
        former_parents = set(entry.parents)

        # Ephemeral dust policy: if this tx is the child that spends an
        # ephemeral dust parent's output, the parent must also be evicted.
        # Reference: Bitcoin Core policy/ephemeral_policy.cpp
        ephemeral_parents_to_evict: list[bytes] = []
        for parent_txid in entry.parents:
            parent_entry = self.transactions.get(parent_txid)
            if parent_entry and parent_entry.has_ephemeral_dust:
                if parent_entry.ephemeral_child == txid:
                    ephemeral_parents_to_evict.append(parent_txid)

        # Remove spent outputs
        for tx_in in entry.tx.inputs:
            outpoint: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            self.spent_outputs.discard(outpoint)

        # Update parent/child links: remove this txid from parents' children sets
        for parent_txid in entry.parents:
            parent_entry = self.transactions.get(parent_txid)
            if parent_entry:
                parent_entry.children.discard(txid)
                # Clear ephemeral child tracking
                if parent_entry.ephemeral_child == txid:
                    parent_entry.ephemeral_child = None

        # Update parent/child links: remove this txid from children's parents sets
        for child_txid in entry.children:
            child_entry = self.transactions.get(child_txid)
            if child_entry:
                child_entry.parents.discard(txid)

        # Remove from sorted list
        if txid in self.by_fee_rate:
            self.by_fee_rate.remove(txid)

        del self.transactions[txid]
        # BIP 152 / BIP 339 dual index — drop the wtxid mapping.  Compute
        # wtxid from the entry we still have a handle on; for non-segwit
        # transactions wtxid == txid.
        try:
            wtxid = entry.tx.get_wtxid()
        except Exception:
            wtxid = txid
        # Defensive: only pop if the wtxid maps back to this txid
        # (the table can briefly disagree if two txs share a wtxid because
        # of equal txid/non-witness, which Core forbids but we don't).
        if self.wtxid_to_txid.get(wtxid) == txid:
            self.wtxid_to_txid.pop(wtxid, None)

        # Update cluster manager
        self._cluster_manager.remove_transaction(txid)

        # Get sequence number for this remove event
        seq = self._next_sequence()

        logger.debug(f"Removed transaction {txid.hex()[:16]}... from mempool (seq: {seq})")

        # Emit notification callback with sequence number
        if self._on_tx_removed is not None:
            try:
                self._on_tx_removed(txid, _reason, seq)
            except Exception as e:
                logger.warning(f"on_tx_removed callback error: {e}")

        if not _skip_recount:
            self._update_descendants_after_removal(txid, former_children, former_parents)

        # Evict ephemeral dust parents (after this tx is fully removed)
        # This must happen after the main removal to avoid modifying entry.parents
        # while iterating over it.
        for parent_txid in ephemeral_parents_to_evict:
            if parent_txid in self.transactions:
                logger.info(
                    f"Evicting ephemeral dust parent {parent_txid.hex()[:16]}... "
                    f"because child {txid.hex()[:16]}... was evicted"
                )
                self._remove_transaction_inner(
                    parent_txid,
                    _skip_recount=_skip_recount,
                    _reason="ephemeral-child-evicted"
                )

    def remove_block_transactions(self, block):
        """
        Remove transactions from mempool that are in a block.

        Args:
            block: Block containing transactions to remove
        """
        with self._lock:
            self._remove_block_transactions_inner(block)

    def _remove_block_transactions_inner(self, block):
        removed_ids: list[bytes] = []
        for tx in block.transactions:
            if not tx.is_coinbase:
                txid = tx.get_txid()
                if txid in self.transactions:
                    self.remove_transaction(txid, _skip_recount=True)
                    removed_ids.append(txid)
                # ClearPrioritisation on block confirm (matches Core
                # removeForBlock — txmempool.cpp:420). Delta is dropped for
                # every block-included tx whether or not it was in mempool.
                self.map_deltas.pop(txid, None)

        # Single-pass recount for all remaining affected transactions
        if removed_ids:
            # Collect all remaining txs and recalculate their counts
            for txid in list(self.transactions):
                self._recalculate_ancestors(txid)
            # Rebuild descendant counts from scratch (more efficient for
            # batch removals than per-tx updates)
            for txid, entry in self.transactions.items():
                descs = self._collect_descendants(txid)
                descs.discard(txid)
                entry.descendant_count = len(descs) + 1
                entry.descendant_size = entry.size + sum(
                    self.transactions[d].size
                    for d in descs if d in self.transactions
                )
            logger.info(
                f"Removed {len(removed_ids)} transactions from mempool "
                f"(included in block)"
            )

        # After each block, reset the rolling fee timestamp and allow decay.
        # Mirrors Bitcoin Core CTxMemPool::removeForBlock() lines 426-427:
        #   lastRollingFeeUpdate = GetTime();
        #   blockSinceLastRollingFeeBump = true;
        self._last_rolling_fee_update = time.time()
        self._block_since_last_rolling_fee_bump = True

    def get_transaction(self, txid: bytes) -> Transaction | None:
        """
        Get transaction from mempool.

        Args:
            txid: Transaction ID

        Returns:
            Transaction or None if not found
        """
        entry = self.transactions.get(txid)
        return entry.tx if entry else None

    def get_all_transactions(self) -> list[Transaction]:
        """
        Get all transactions in mempool.

        Returns:
            List of all transactions
        """
        txs = [entry.tx for entry in self.transactions.values()]
        return txs

    def get_transactions_by_fee_rate(self, limit: int | None = None) -> list[Transaction]:
        """
        Get transactions sorted by fee rate (highest first).

        Args:
            limit: Maximum number of transactions to return

        Returns:
            List of transactions sorted by fee rate (highest first)
        """
        # by_fee_rate is sorted lowest to highest, so we reverse it
        txids = self.by_fee_rate[-limit:] if limit else self.by_fee_rate
        return [self.transactions[txid].tx for txid in reversed(txids)]

    def get_mempool_info(self) -> dict:
        """
        Get mempool statistics.

        Returns:
            Dictionary with mempool statistics
        """
        if not self.transactions:
            return {
                'size': 0,
                'bytes': 0,
                'max_size': self.max_size,
                'min_fee_rate': 0,
                'max_fee_rate': 0,
                'avg_fee_rate': 0,
            }

        fee_rates = [entry.fee_rate for entry in self.transactions.values()]

        return {
            'size': len(self.transactions),
            'bytes': self.current_size,
            'max_size': self.max_size,
            'min_fee_rate': min(fee_rates),
            'max_fee_rate': max(fee_rates),
            'avg_fee_rate': sum(fee_rates) / len(fee_rates),
            'orphan_count': self.orphan_pool.size(),
            'cluster_count': len(self._cluster_manager._clusters),
        }

    # ── Cluster Mempool Mining Interface ─────────────────────────────────

    def get_mining_chunks(self) -> list[tuple[Chunk, list[bytes]]]:
        """Get chunks for block template construction, sorted by feerate.

        Returns a list of (chunk, txids) tuples, where txids are in
        topological order (parents before children) within each chunk.
        Chunks are sorted by fee rate, highest first.

        Reference: Bitcoin Core txgraph.h - GetBlockBuilder()
        """
        with self._lock:
            result: list[tuple[Chunk, list[bytes]]] = []

            for chunk, _cluster_id in self._cluster_manager.get_mining_chunks():
                # Get topologically sorted txids within chunk
                linearizer = ClusterLinearizer(self.transactions)
                sorted_txids = linearizer._topo_sort(chunk.txids)
                result.append((chunk, sorted_txids))

            return result

    def get_block_template_txs(
        self, max_weight: int = 4_000_000
    ) -> tuple[list[Transaction], int]:
        """Select transactions for a block template using cluster linearization.

        Selects chunks in decreasing feerate order until the weight limit
        is reached. Returns transactions in mining order (topologically
        sorted within each chunk, chunks sorted by fee rate).

        Args:
            max_weight: Maximum block weight (default 4M = 1M vbytes)

        Returns:
            (transactions, total_fee) - list of transactions to include and
            their total fee
        """
        with self._lock:
            selected_txs: list[Transaction] = []
            total_fee = 0
            total_weight = 0

            for chunk, txids in self.get_mining_chunks():
                # Approximate weight as 4 * size (conservative)
                chunk_weight = chunk.total_size * 4

                if total_weight + chunk_weight > max_weight:
                    # Can't fit this chunk, skip it
                    # In a more sophisticated impl, we could try smaller chunks
                    continue

                # Add all transactions in this chunk
                for txid in txids:
                    entry = self.transactions.get(txid)
                    if entry:
                        selected_txs.append(entry.tx)

                total_fee += chunk.total_fee
                total_weight += chunk_weight

            return selected_txs, total_fee

    def get_cluster_info(self, txid: bytes) -> dict | None:
        """Get cluster information for a transaction.

        Returns dict with cluster_id, cluster_size, linearization position,
        and chunk info for the transaction.
        """
        with self._lock:
            cluster = self._cluster_manager.get_cluster(txid)
            if cluster is None:
                return None

            cluster_id = self._cluster_manager.get_cluster_id(txid)
            linearization = self._cluster_manager.get_linearization(cluster)
            chunks = self._cluster_manager.get_chunks(cluster)

            # Find which chunk this tx is in and its position
            chunk_index = None
            chunk_fee_rate = None
            for i, chunk in enumerate(chunks):
                if txid in chunk.txids:
                    chunk_index = i
                    chunk_fee_rate = chunk.fee_rate
                    break

            lin_position = linearization.index(txid) if txid in linearization else None

            return {
                'cluster_id': cluster_id,
                'cluster_size': cluster.size(),
                'linearization_position': lin_position,
                'chunk_index': chunk_index,
                'chunk_fee_rate': chunk_fee_rate,
                'num_chunks': len(chunks),
            }

    # BIP 125 Replace-By-Fee #

    INCREMENTAL_RELAY_FEE = DEFAULT_INCREMENTAL_RELAY_FEE  # 100 sat/kvB (Core DEFAULT_INCREMENTAL_RELAY_FEE)
    MAX_REPLACEMENT_EVICTIONS = 100

    def _check_cluster_rbf(
        self, new_tx: Transaction, to_evict: set[bytes], new_fee: int
    ) -> tuple[bool, str]:
        """Check if replacement improves the cluster linearization.

        For cluster mempool, we require that the new linearization be strictly
        better than the old one. This is checked by comparing feerate diagrams.

        The feerate diagram is a cumulative plot of (size, fee) for each chunk
        in order. A diagram A is better than B if A is always above B.

        Reference: Bitcoin Core txgraph.h - GetMainStagingDiagrams()
        """
        # Find clusters affected by the eviction
        affected_cluster_ids: set[int] = set()
        for txid in to_evict:
            cid = self._cluster_manager.get_cluster_id(txid)
            if cid is not None:
                affected_cluster_ids.add(cid)

        if not affected_cluster_ids:
            # No clusters affected - OK
            return True, ""

        # Get old feerate diagrams for affected clusters
        old_diagrams: list[list[tuple[int, int]]] = []  # List of [(size, fee), ...]
        for cid in affected_cluster_ids:
            cluster = self._cluster_manager._clusters.get(cid)
            if cluster:
                chunks = self._cluster_manager.get_chunks(cluster)
                diagram = []
                cumul_size = 0
                cumul_fee = 0
                for chunk in chunks:
                    cumul_size += chunk.total_size
                    cumul_fee += chunk.total_fee
                    diagram.append((cumul_size, cumul_fee))
                old_diagrams.append(diagram)

        # Compute what the new diagram would look like after replacement
        # This is approximate: we simulate adding the new tx after eviction
        new_size = len(new_tx.serialize())

        # Calculate total old MODIFIED fee/size from affected clusters
        # (FIX-72) — diagram comparisons must honour prioritisetransaction so
        # that a user-prioritised victim looks expensive to the RBF gate.
        old_total_fee = 0
        old_total_size = 0
        for cid in affected_cluster_ids:
            cluster = self._cluster_manager._clusters.get(cid)
            if cluster:
                for txid in cluster.txids:
                    entry = self.transactions.get(txid)
                    if entry:
                        old_total_fee += self.get_modified_fee(entry)
                        old_total_size += entry.size

        # Calculate new total after eviction + addition (use MODIFIED fee on
        # the evicted side; new_fee already includes the replacement's delta).
        evicted_fee = sum(
            self.get_modified_fee(t)
            for t in to_evict
            if t in self.transactions
        )
        evicted_size = sum(self.transactions[t].size for t in to_evict if t in self.transactions)

        new_total_fee = old_total_fee - evicted_fee + new_fee
        new_total_size = old_total_size - evicted_size + new_size

        # Simple check: the new fee rate must be >= old fee rate
        # This is a simplified version of the full diagram comparison
        old_rate = old_total_fee / old_total_size if old_total_size > 0 else 0
        new_rate = new_total_fee / new_total_size if new_total_size > 0 else 0

        if new_rate < old_rate:
            return False, (
                f"Replacement would worsen cluster feerate: "
                f"{new_rate:.2f} < {old_rate:.2f} sat/vB"
            )

        # Additional check: the new tx's feerate should be at least as good as
        # the worst chunk it would displace
        new_tx_rate = new_fee / new_size if new_size > 0 else 0
        for cid in affected_cluster_ids:
            cluster = self._cluster_manager._clusters.get(cid)
            if cluster:
                chunks = self._cluster_manager.get_chunks(cluster)
                if chunks:
                    # Check against chunks containing evicted txs
                    for chunk in chunks:
                        if chunk.txids & to_evict:
                            # This chunk contains evicted txs
                            # New tx should have at least this feerate
                            if new_tx_rate < chunk.fee_rate * 0.99:  # 1% tolerance
                                return False, (
                                    f"Replacement tx feerate {new_tx_rate:.2f} is worse "
                                    f"than chunk feerate {chunk.fee_rate:.2f}"
                                )

        return True, ""

    def _find_conflicts(self, tx: Transaction) -> set[bytes]:
        conflicts: set[bytes] = set()
        for tx_in in tx.inputs:
            op: OutPoint = (tx_in.prev_txid, tx_in.prev_vout)
            if op in self.spent_outputs:
                for txid, entry in self.transactions.items():
                    for existing_in in entry.tx.inputs:
                        if (existing_in.prev_txid, existing_in.prev_vout) == op:
                            conflicts.add(txid)
        return conflicts

    def _collect_descendants(self, txid: bytes) -> set[bytes]:
        """Get all descendants (transitive children) of a transaction.

        Uses children links stored on MempoolEntry for efficient traversal.
        """
        result: set[bytes] = {txid}
        queue: list[bytes] = [txid]
        while queue:
            parent_txid = queue.pop()
            parent_entry = self.transactions.get(parent_txid)
            if parent_entry is None:
                continue
            # Use stored children links for efficient traversal
            for child_txid in parent_entry.children:
                if child_txid not in result and child_txid in self.transactions:
                    result.add(child_txid)
                    queue.append(child_txid)
        return result

    def signals_rbf(self, tx: Transaction) -> bool:
        """Check if a transaction signals opt-in RBF per BIP125.

        A transaction signals RBF if any input has nSequence <= MAX_BIP125_RBF_SEQUENCE
        (0xFFFFFFFD).  Inputs with nSequence 0xFFFFFFFE or 0xFFFFFFFF do NOT signal.
        This allows opt-out of replacement while still using nLockTime
        (nSequence = 0xFFFFFFFE).

        Reference: bitcoin/src/util/rbf.cpp SignalsOptInRBF()
                   bitcoin/src/util/rbf.h MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD
        """
        MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD
        return any(inp.sequence <= MAX_BIP125_RBF_SEQUENCE for inp in tx.inputs)

    def is_rbf_opt_in(self, txid: bytes) -> bool:
        """Check if a mempool transaction is replaceable.

        A tx is replaceable if:
        1. The transaction is a TRUC (v3) transaction (always replaceable), OR
        2. The transaction itself signals RBF (any input sequence <= 0xFFFFFFFD), OR
        3. Any of its unconfirmed ancestors signal RBF, OR
        4. Any of its unconfirmed ancestors is a TRUC (v3) transaction

        Reference: bitcoin/src/policy/rbf.cpp IsRBFOptIn()
        """
        entry = self.transactions.get(txid)
        if entry is None:
            return False

        # TRUC (v3) transactions are always replaceable
        if self._is_truc(entry.tx):
            return True

        # Check if this tx signals
        if self.signals_rbf(entry.tx):
            return True

        # Check if any ancestor signals or is TRUC
        ancestors = self._get_ancestors(entry.tx)
        for anc_txid in ancestors:
            anc_entry = self.transactions.get(anc_txid)
            if anc_entry:
                if self.signals_rbf(anc_entry.tx):
                    return True
                if self._is_truc(anc_entry.tx):
                    return True

        return False

    def try_replace(
        self, new_tx: Transaction, height: int
    ) -> tuple[bool, str]:
        """
        BIP 125 Replace-By-Fee.

        BIP 125 rules enforced (bitcoin/src/policy/rbf.cpp):
        Gate 1 — SignalsOptInRBF: every directly-conflicting tx must signal
          replaceability (any input nSequence <= 0xFFFFFFFD), or a mempool
          ancestor must signal; unless full_rbf is enabled.
        Gate 2 — Ancestor inheritance: is_rbf_opt_in() walks mempool ancestors.
        Gate 3 — Rule #5 MAX_REPLACEMENT_CANDIDATES=100: the eviction set
          (direct conflicts + all descendants) must not exceed 100 entries.
        Gate 4 — Rule #2 HasNoNewUnconfirmed: the replacement must not spend
          any unconfirmed inputs that were not already spent by the eviction set.
        Gate 5 — EntriesAndTxidsDisjoint: the replacement's mempool ancestors
          must not include any directly-conflicting transactions.
        Gate 6 — Rule #3 PaysForRBF (absolute): replacement_fees >= original_fees.
        Gate 7 — Rule #4 PaysForRBF (incremental): additional_fees >=
          incrementalrelayfee * replacement_vsize.

        Returns (success, error_message).  On success the conflicts
        (and their descendants) are removed and the new tx is added.
        """
        with self._lock:
            return self._try_replace_inner(new_tx, height)

    def _try_replace_inner(
        self, new_tx: Transaction, height: int
    ) -> tuple[bool, str]:
        """Unlocked implementation of try_replace."""
        conflicts = self._find_conflicts(new_tx)
        if not conflicts:
            return False, "No conflicts to replace"

        # TRUC (v3) replacement constraints
        if new_tx.version == 3:
            # The replacement itself must obey v3 ancestor limits.
            # After evicting conflicts we should end up with ≤ 1
            # unconfirmed ancestor.  Pre-check: count unconfirmed
            # parents that are NOT being evicted.
            remaining_ancestors: set[bytes] = set()
            for inp in new_tx.inputs:
                if inp.prev_txid in self.transactions and inp.prev_txid not in conflicts:
                    remaining_ancestors.add(inp.prev_txid)
                    # Also walk up the ancestor chain
                    parent_entry = self.transactions.get(inp.prev_txid)
                    if parent_entry:
                        for a in self._get_ancestors(parent_entry.tx):
                            if a not in conflicts:
                                remaining_ancestors.add(a)
            if len(remaining_ancestors) + 1 > TX_V3_ANCESTOR_LIMIT:
                return False, (
                    f"TRUC (v3) replacement exceeds unconfirmed ancestor "
                    f"limit: {len(remaining_ancestors) + 1} > "
                    f"{TX_V3_ANCESTOR_LIMIT}"
                )

            # If replacing a child of a v3 parent, the new child vsize
            # must still be ≤ TX_V3_MAX_VSIZE.
            for inp in new_tx.inputs:
                parent_entry = self.transactions.get(inp.prev_txid)
                if parent_entry is not None and parent_entry.tx.version == 3:
                    tx_vsize = (
                        new_tx.get_vsize()
                        if hasattr(new_tx, 'get_vsize')
                        else len(new_tx.serialize())
                    )
                    if tx_vsize > TX_V3_MAX_VSIZE:
                        return False, (
                            f"TRUC (v3) replacement child vsize {tx_vsize} "
                            f"exceeds {TX_V3_MAX_VSIZE} limit"
                        )

        # Rule 1: all direct conflicts must signal replaceability
        # UNLESS full_rbf (mempoolfullrbf) is enabled
        if not self.full_rbf:
            for c_txid in conflicts:
                self.transactions[c_txid]
                if not self.is_rbf_opt_in(c_txid):
                    return False, "Conflicting tx does not signal replaceability (BIP125)"

        # Gather full eviction set (conflicts + descendants)
        to_evict: set[bytes] = set()
        for c_txid in conflicts:
            to_evict |= self._collect_descendants(c_txid)

        # Gate 3 — Rule #5 MAX_REPLACEMENT_CANDIDATES: The eviction set
        # (direct conflicts + all their descendants) must not exceed 100 entries.
        # Core uses GetUniqueClusterCount(); without cluster mempool we count
        # total evictees as a conservative bound (same limit, same intent).
        # Reference: bitcoin/src/policy/rbf.cpp GetEntriesForConflicts() lines 68-75
        if len(to_evict) > self.MAX_REPLACEMENT_EVICTIONS:
            return False, (
                f"Replacement would evict {len(to_evict)} txs; "
                f"too many potential replacements (max {self.MAX_REPLACEMENT_EVICTIONS})"
            )

        # Rule #2 (HasNoNewUnconfirmed): The replacement must not introduce any
        # new unconfirmed inputs that were not already spent by the to-be-evicted
        # transactions.  A "new unconfirmed input" is any input whose prev_txid is
        # still in the mempool (i.e. unconfirmed) and is not an output being freed
        # by the eviction set.
        #
        # Reference: BIP 125 Rule #2; bitcoin/src/validation.cpp ReplacementChecks()
        old_unconfirmed: set[OutPoint] = set()
        for evict_txid in to_evict:
            evict_entry = self.transactions[evict_txid]
            for inp in evict_entry.tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                # An input is "unconfirmed" if its parent is still in the mempool
                # (and therefore not yet confirmed).  Note: if the parent is also
                # in to_evict, it is being freed — those outputs become available.
                if inp.prev_txid in self.transactions:
                    old_unconfirmed.add(op)
        for inp in new_tx.inputs:
            op = (inp.prev_txid, inp.prev_vout)
            if inp.prev_txid in self.transactions and op not in old_unconfirmed:
                return False, (
                    f"Replacement {new_tx.get_txid().hex()[:16]}... introduces "
                    f"new unconfirmed input ({inp.prev_txid.hex()[:16]}...:{inp.prev_vout})"
                )

        # EntriesAndTxidsDisjoint: the replacement tx must not spend an output of
        # any transaction it is replacing (that would be a self-spending loop).
        # Equivalently: the new tx's mempool ancestors must not include any of the
        # direct conflicts.
        #
        # Reference: bitcoin/src/policy/rbf.cpp EntriesAndTxidsDisjoint()
        #            bitcoin/src/validation.cpp:1356
        new_tx_ancestors = self._get_ancestors(new_tx)
        for anc_txid in new_tx_ancestors:
            if anc_txid in conflicts:
                anc_hex = anc_txid.hex()[:16]
                return False, (
                    f"Replacement {new_tx.get_txid().hex()[:16]}... spends "
                    f"conflicting transaction {anc_hex}..."
                )

        # Calculate new tx fee
        new_size = len(new_tx.serialize())
        total_input = 0
        for inp in new_tx.inputs:
            utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo:
                total_input += utxo['value']
        total_output = sum(out.value for out in new_tx.outputs)
        new_fee = total_input - total_output

        # Modified-fee accounting (FIX-72): Core ReplacementChecks uses
        # CTxMemPoolEntry::GetModifiedFee() = nFee + nFeeDelta everywhere
        # (rbf.cpp:74, 107-111, 117-122).  Apply pending prioritisetransaction
        # delta to the replacement and to each evicted entry so that operator
        # priority is honoured on both sides of the comparison.
        # Reference: bitcoin-core/src/policy/rbf.cpp PaysForRBF;
        #            bitcoin-core/src/kernel/mempool_entry.h GetModifiedFee.
        new_txid_for_delta = new_tx.get_txid()
        new_fee_modified = new_fee + int(self.map_deltas.get(new_txid_for_delta, 0))
        # Sum of MODIFIED fees from all evicted transactions
        old_fees = sum(
            self.get_modified_fee(t) for t in to_evict
        )

        # Rule #3 (PaysForRBF, part 1): The replacement fees must be greater than
        # or equal to fees of the transactions it replaces.
        # Core: reject if replacement_fees < original_fees (i.e. allow equal fees).
        # Reference: bitcoin/src/policy/rbf.cpp PaysForRBF() lines 107-111
        # Uses MODIFIED fees on both sides (Core: GetModifiedFee()).
        if new_fee_modified < old_fees:
            return False, (
                f"Replacement fee {new_fee_modified} sat is less than "
                f"evicted fees {old_fees} sat"
            )

        # Rule #4 (PaysForRBF, part 2): The additional fees must pay for the
        # replacement's own bandwidth at or above the incremental relay feerate.
        # additional_fees = replacement_fees - original_fees
        # additional_fees >= incrementalrelayfee * replacement_vsize / 1000
        # Reference: bitcoin/src/policy/rbf.cpp PaysForRBF() lines 117-122
        # Uses MODIFIED fees on both sides.
        incremental_fee_needed = (new_size * self.INCREMENTAL_RELAY_FEE) // 1000
        additional_fee = new_fee_modified - old_fees
        if additional_fee < incremental_fee_needed:
            return False, (
                f"Replacement does not cover incremental relay fee: "
                f"additional {additional_fee} sat < required {incremental_fee_needed} sat"
            )

        # Rule 6 (cluster mempool): new linearization must be strictly better
        # The new tx must improve the feerate diagram of the affected cluster(s).
        # Reference: Bitcoin Core txgraph.h - GetMainStagingDiagrams()
        # Pass the MODIFIED fee so diagram comparisons honour prioritisation.
        cluster_ok, cluster_err = self._check_cluster_rbf(
            new_tx, to_evict, new_fee_modified
        )
        if not cluster_ok:
            return False, cluster_err

        # All checks passed — evict and add (skip per-removal recount)
        evicted_ids = set(to_evict)
        for txid in to_evict:
            self.remove_transaction(txid, _skip_recount=True, _reason="replaced")

        new_fee_rate = new_fee / new_size if new_size > 0 else 0
        new_txid = new_tx.get_txid()

        # Compute direct parents and ancestors for the replacement tx
        direct_parents: set[bytes] = set()
        for inp in new_tx.inputs:
            if inp.prev_txid in self.transactions:
                direct_parents.add(inp.prev_txid)

        ancestors = self._get_ancestors(new_tx)
        ancestor_size = sum(
            self.transactions[a].size for a in ancestors if a in self.transactions
        )
        entry = MempoolEntry(
            tx=new_tx, fee=new_fee, fee_rate=new_fee_rate,
            size=new_size, time_added=time.time(), height_added=height,
            ancestor_count=len(ancestors) + 1,
            ancestor_size=ancestor_size + new_size,
            parents=direct_parents,
            children=set(),
        )
        self.transactions[new_txid] = entry
        self.current_size += new_size
        for inp in new_tx.inputs:
            self.spent_outputs.add((inp.prev_txid, inp.prev_vout))
        self._insert_sorted_by_fee_rate(new_txid, new_fee_rate)

        # Update parent entries to add this txid as a child
        for parent_txid in direct_parents:
            if parent_txid in self.transactions:
                self.transactions[parent_txid].children.add(new_txid)

        # Update ancestor descendant counts for the new tx's ancestors
        for a_txid in ancestors:
            if a_txid in self.transactions:
                self.transactions[a_txid].descendant_count += 1
                self.transactions[a_txid].descendant_size += new_size

        # Single-pass recount for all remaining txs affected by evictions
        for evicted_id in evicted_ids:
            self._update_descendants_after_removal(evicted_id)

        logger.info(
            f"RBF: replaced {len(to_evict)} tx(s) with "
            f"{new_txid.hex()[:16]}... (fee {new_fee}, "
            f"rate {new_fee_rate:.2f} sat/vB)"
        )
        return True, ""

    def _insert_sorted_by_fee_rate(self, txid: bytes, fee_rate: float):
        # Binary search and insert (maintains sorted order: lowest to highest)
        left, right = 0, len(self.by_fee_rate)

        while left < right:
            mid = (left + right) // 2
            mid_entry = self.transactions[self.by_fee_rate[mid]]
            if mid_entry.fee_rate < fee_rate:
                left = mid + 1
            else:
                right = mid

        self.by_fee_rate.insert(left, txid)

    def _evict_low_fee_txs(self, needed_space: int):
        """Evict lowest-feerate chunks until we have enough space.

        Uses cluster mempool chunk-based eviction: we evict whole chunks
        (groups of transactions that would be mined together) rather than
        individual transactions. This maintains linearization invariants.

        After each chunk is removed, trackPackageRemoved is called so that the
        rolling minimum fee rate rises to (evicted_chunk_feerate +
        INCREMENTAL_RELAY_FEE), preventing the evicted transactions from
        immediately re-entering the pool.

        Reference: Bitcoin Core txmempool.cpp:861-911 TrimToSize() +
                   txmempool.cpp:853-859 trackPackageRemoved().
        """
        freed = 0
        evicted_count = 0
        max_fee_rate_removed: float = 0.0

        # Evict entire chunks (lowest feerate first)
        while self.transactions and freed < needed_space:
            worst = self._cluster_manager.get_worst_chunk()
            if worst is None:
                break

            chunk, _cluster_id = worst
            chunk_size = chunk.total_size

            # Compute the chunk feerate in sat/kvB for trackPackageRemoved.
            # Core: removed = CFeeRate(feerate.fee, feerate.size)
            #       removed += m_opts.incremental_relay_feerate
            #       trackPackageRemoved(removed)
            chunk_fee_per_kvb: float = 0.0
            if chunk.total_size > 0:
                # chunk.fee_rate is sat/vB; convert to sat/kvB
                chunk_fee_per_kvb = chunk.fee_rate * 1000.0
            # Add incremental relay fee (Core: removed += incremental_relay_feerate)
            removed_fee_per_kvb = chunk_fee_per_kvb + DEFAULT_INCREMENTAL_RELAY_FEE
            self._track_package_removed(removed_fee_per_kvb)
            if removed_fee_per_kvb > max_fee_rate_removed:
                max_fee_rate_removed = removed_fee_per_kvb

            # Evict all transactions in this chunk
            # Must remove in reverse topological order (children before parents)
            # to avoid orphaning transactions
            chunk_txids = list(chunk.txids)
            # Sort by descendant count (highest first = children first)
            chunk_txids.sort(
                key=lambda t: self.transactions[t].descendant_count
                if t in self.transactions else 0,
                reverse=True
            )

            for txid in chunk_txids:
                if txid in self.transactions:
                    self._remove_transaction_inner(txid, _reason="evicted")
                    evicted_count += 1

            freed += chunk_size

        if evicted_count > 0:
            logger.info(
                f"Evicted {evicted_count} transactions (chunk-based) to free "
                f"{freed} bytes (needed: {needed_space}); "
                f"rolling min fee bumped to {max_fee_rate_removed:.1f} sat/kvB"
            )

    def clear(self) -> None:
        """Clear all transactions from the mempool."""
        with self._lock:
            count = len(self.transactions)
            self.transactions.clear()
            self.wtxid_to_txid.clear()
            self.spent_outputs.clear()
            self.by_fee_rate.clear()
            self._cluster_manager.rebuild()  # Clear cluster data
            self.current_size = 0
            logger.info(f"Cleared mempool ({count} transactions removed)")

    # Persistence
    # ──────────────────────────────────────────────────────────────────────────
    # mempool.dat format — Bitcoin Core compatible (kernel/mempool_persist.cpp)
    #
    # Reference: Bitcoin Core src/node/mempool_persist.cpp DumpMempool/LoadMempool.
    #
    # Layout (all little-endian, no padding):
    #   uint64 version              = 1 (no XOR) or 2 (XOR-obfuscated)
    #   if version == 2:
    #       compact_size key_len    = 8
    #       byte[8]    xor_key      (random; first 8 bytes that follow are XORed
    #                                with this key, repeating)
    #   uint64 tx_count
    #   per tx:
    #       CTransaction (TX_WITH_WITNESS — segwit-marker form)
    #       int64  nTime            (seconds since UNIX epoch)
    #       int64  nFeeDelta
    #   compact_size mapDeltas_count
    #     per mapDeltas entry:
    #       byte[32] txid           (Core's Txid, internal byte order)
    #       int64    delta          (CAmount)
    #   compact_size unbroadcast_count
    #     per unbroadcast entry:
    #       byte[32] txid
    #
    # The XOR key is applied byte-wise starting AFTER the obfuscation header
    # (i.e. the version + key bytes are stored in plaintext; everything that
    # follows is XOR-obfuscated).  Position-aware: byte[i_after_header] ^=
    # xor_key[i_after_header % 8].
    # ──────────────────────────────────────────────────────────────────────────

    MEMPOOL_DUMP_VERSION_NO_XOR_KEY = 1
    MEMPOOL_DUMP_VERSION = 2  # default: XOR-obfuscated (Core ≥ v25)

    @staticmethod
    def _write_compact_size(buf: bytearray, n: int) -> None:
        """Append a CompactSize-encoded uint to *buf* (Bitcoin serialize.h)."""
        if n < 253:
            buf.append(n)
        elif n <= 0xFFFF:
            buf.append(253)
            buf.extend(struct.pack("<H", n))
        elif n <= 0xFFFFFFFF:
            buf.append(254)
            buf.extend(struct.pack("<I", n))
        else:
            buf.append(255)
            buf.extend(struct.pack("<Q", n))

    @staticmethod
    def _read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
        """Decode a CompactSize-encoded uint at *offset*; returns (value, new_offset)."""
        if offset >= len(data):
            raise ValueError("Truncated CompactSize")
        first = data[offset]
        offset += 1
        if first < 253:
            return first, offset
        if first == 253:
            if offset + 2 > len(data):
                raise ValueError("Truncated CompactSize<u16>")
            return struct.unpack_from("<H", data, offset)[0], offset + 2
        if first == 254:
            if offset + 4 > len(data):
                raise ValueError("Truncated CompactSize<u32>")
            return struct.unpack_from("<I", data, offset)[0], offset + 4
        if offset + 8 > len(data):
            raise ValueError("Truncated CompactSize<u64>")
        return struct.unpack_from("<Q", data, offset)[0], offset + 8

    @staticmethod
    def _xor_obfuscate(payload: bytearray, key: bytes) -> None:
        """Apply Core's position-aware XOR-obfuscation to *payload* in place.

        Each byte at index ``i`` in the payload is XORed with ``key[i % 8]``,
        matching ``util/obfuscation.h`` Obfuscation::operator() with
        ``key_offset = 0``.  This is symmetric, so the same routine handles
        both serialization and deserialization.
        """
        if not key or all(b == 0 for b in key):
            return
        klen = len(key)
        for i in range(len(payload)):
            payload[i] ^= key[i % klen]

    def dump_to_file(self, filepath: str, *, use_xor: bool = True) -> int:
        """Persist mempool to *filepath* in Bitcoin Core's mempool.dat format.

        ``use_xor=True`` (the default) writes version 2 with a random 8-byte
        XOR-obfuscation key, matching ``persist_v1_dat = false`` in Core.
        ``use_xor=False`` writes version 1 (plaintext); useful for tests.

        Returns the number of transactions written (0 if mempool is empty
        AND no standalone deltas exist, in which case any stale file at
        *filepath* is removed).  Note: when ``map_deltas`` is non-empty even
        if ``transactions`` is empty, the file IS written so deltas persist
        across restart (FIX-76, Core parity).
        """
        count = len(self.transactions)
        if count == 0 and not self.map_deltas:
            # Remove stale file
            try:
                os.remove(filepath)
            except FileNotFoundError:
                pass
            return 0

        # Build the obfuscated payload first; the version + xor-key header
        # is written in plaintext after the payload is XORed.
        #
        # FIX-76 (W120 brief-error closure for FIX-72): mapDeltas is now
        # persisted across restart, matching Core
        # (node/mempool_persist.cpp:101+166-203).  In-mempool entries write
        # their delta in the per-tx nFeeDelta field.  Remaining standalone
        # deltas (for txids NOT currently in the mempool) ride along in the
        # mapDeltas tail block, exactly as Core does (deltas erased from the
        # working set after the per-tx loop, see line 200 in
        # mempool_persist.cpp).
        body = bytearray()
        body.extend(struct.pack("<Q", count))  # uint64 mempool_transactions_to_write
        # Snapshot under-lock once; we then mutate the LOCAL copy as we walk
        # entries so the post-loop tail block only contains standalone deltas.
        with self._lock:
            map_deltas_remaining = dict(self.map_deltas)
        for entry in self.transactions.values():
            raw = entry.tx.serialize_with_witness()
            body.extend(raw)
            body.extend(struct.pack("<q", int(entry.time_added)))  # int64 nTime
            # nFeeDelta for in-mempool entry — pulled from map_deltas.
            txid = entry.tx.get_txid()
            n_fee_delta = int(map_deltas_remaining.pop(txid, 0))
            body.extend(struct.pack("<q", n_fee_delta))  # int64 nFeeDelta
        # mapDeltas tail — standalone deltas for txids NOT in mempool entries.
        # Core layout: compact_size count, then per entry: byte[32] txid + int64.
        self._write_compact_size(body, len(map_deltas_remaining))
        for txid, delta in map_deltas_remaining.items():
            if len(txid) != 32:
                # Defensive: skip malformed entries rather than corrupt the file.
                continue
            body.extend(txid)
            body.extend(struct.pack("<q", int(delta)))
        # unbroadcast_txids — empty (we don't track unbroadcast set yet)
        self._write_compact_size(body, 0)

        if use_xor:
            xor_key = os.urandom(8)
            self._xor_obfuscate(body, xor_key)
            version = self.MEMPOOL_DUMP_VERSION
        else:
            xor_key = b""
            version = self.MEMPOOL_DUMP_VERSION_NO_XOR_KEY

        tmp = filepath + ".new"  # match Core's ".new" temp name
        try:
            with open(tmp, "wb") as f:
                f.write(struct.pack("<Q", version))
                if use_xor:
                    # compact_size(8) prefix + 8-byte key (Vec<byte>)
                    header = bytearray()
                    self._write_compact_size(header, len(xor_key))
                    header.extend(xor_key)
                    f.write(bytes(header))
                f.write(bytes(body))
            os.replace(tmp, filepath)
            logger.info(
                f"Saved {count} mempool transactions to {filepath} "
                f"(format=v{version})"
            )
            return count
        except Exception as e:
            logger.warning(f"Failed to dump mempool: {e}")
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
            return 0

    def _load_legacy_format(
        self, raw: bytes, height: int
    ) -> tuple[int, int]:
        """Best-effort load from the pre-Core ``v1 byte`` dump format.

        Returns ``(loaded, skipped)``.  Old format:
            uint8 version=1, uint32 count, repeat[uint32 raw_len, raw,
            int64 fee, double time_added].
        """
        from ouroboros.p2p_messages import TxMessage

        loaded = 0
        skipped = 0
        offset = 0
        if len(raw) < 5:
            return 0, 0
        # Skip 1-byte version + 4-byte count
        count = struct.unpack_from("<I", raw, 1)[0]
        offset = 5
        for _ in range(count):
            if offset + 4 > len(raw):
                break
            raw_len = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            if offset + raw_len + 16 > len(raw):
                break
            tx_bytes = raw[offset:offset + raw_len]
            offset += raw_len
            time_added = struct.unpack_from("<d", raw, offset + 8)[0]
            offset += 16
            try:
                tx = TxMessage.from_payload(tx_bytes).transaction
            except Exception:
                skipped += 1
                continue
            ok, _err = self.add_transaction(tx, height)
            if ok:
                txid = tx.get_txid()
                if txid in self.transactions:
                    self.transactions[txid].time_added = time_added
                loaded += 1
            else:
                skipped += 1
        return loaded, skipped

    def load_from_file(self, filepath: str, height: int) -> int:
        """Reload mempool from a Bitcoin Core compatible ``mempool.dat``.

        Each transaction is re-validated before being accepted (UTXOs may
        have changed since the dump was written).  Transactions that fail
        validation are silently skipped.

        The legacy custom format produced by ouroboros < 2026-04-29 is
        auto-detected and converted: txs are re-loaded from the old layout
        and the file is rewritten in Core format on next dump.

        FIX-76: prioritisation deltas (mapDeltas) are restored on load,
        both per-entry (nFeeDelta in tx record) and standalone (tail block
        for txids not currently in the mempool).  Matches Core
        node/mempool_persist.cpp:99-102 + 125-132.

        Returns the number of transactions successfully loaded.
        """
        from ouroboros.p2p_messages import TxMessage

        if not os.path.exists(filepath):
            return 0

        loaded = 0
        skipped = 0
        try:
            with open(filepath, "rb") as f:
                raw = f.read()

            if len(raw) < 8:
                return 0

            # Auto-detect format. Core writes uint64 version in [1, 2].
            # Legacy ouroboros wrote uint8 version=1, so the first 8 bytes
            # interpreted as uint64 LE will almost always exceed 2.
            version = struct.unpack_from("<Q", raw, 0)[0]
            if version not in (
                self.MEMPOOL_DUMP_VERSION_NO_XOR_KEY,
                self.MEMPOOL_DUMP_VERSION,
            ):
                # Fall back to legacy custom format.
                logger.info(
                    f"mempool.dat at {filepath} is in legacy ouroboros "
                    "format; converting on next dump"
                )
                loaded, skipped = self._load_legacy_format(raw, height)
                logger.info(
                    f"Loaded {loaded} mempool transactions from {filepath}"
                    + (f" ({skipped} skipped)" if skipped else "")
                )
                # Remove old-format file so the next dump writes Core format
                try:
                    os.remove(filepath)
                except FileNotFoundError:
                    pass
                return loaded

            offset = 8
            xor_key = b""
            if version == self.MEMPOOL_DUMP_VERSION:
                # Read xor_key (Vec<byte> = compact_size + bytes)
                key_len, offset = self._read_compact_size(raw, offset)
                if key_len != 8:
                    logger.warning(
                        f"mempool.dat XOR key has unexpected length "
                        f"{key_len}, expected 8"
                    )
                    return 0
                xor_key = raw[offset:offset + key_len]
                offset += key_len

            # XOR-deobfuscate the rest of the file in place
            body = bytearray(raw[offset:])
            self._xor_obfuscate(body, xor_key)
            body = bytes(body)
            offset = 0

            if len(body) < 8:
                return 0
            tx_count = struct.unpack_from("<Q", body, offset)[0]
            offset += 8

            for _ in range(tx_count):
                # Parse one CTransaction-with-witness from `body[offset:]`.
                # TxMessage.from_payload sets bytes_consumed for us.
                try:
                    tx_msg = TxMessage.from_payload(body[offset:])
                    consumed = getattr(tx_msg, "bytes_consumed", 0)
                except Exception as e:
                    logger.warning(f"Failed to parse tx in mempool.dat: {e}")
                    skipped += 1
                    break
                offset += consumed

                # int64 nTime + int64 nFeeDelta
                if offset + 16 > len(body):
                    break
                n_time = struct.unpack_from("<q", body, offset)[0]
                offset += 8
                n_fee_delta = struct.unpack_from("<q", body, offset)[0]
                offset += 8

                tx = tx_msg.transaction
                ok, _err = self.add_transaction(tx, height)
                if ok:
                    txid = tx.get_txid()
                    if txid in self.transactions:
                        self.transactions[txid].time_added = float(n_time)
                    # FIX-76: restore per-tx nFeeDelta into map_deltas (Core
                    # parity: mempool_persist.cpp:99-102 PrioritiseTransaction
                    # for every recovered entry with non-zero delta).
                    if n_fee_delta != 0:
                        self.prioritise_transaction(tx.get_txid(), int(n_fee_delta))
                    loaded += 1
                else:
                    skipped += 1
                    # Even on validation failure, Core honours the on-disk
                    # delta for that txid (so if the tx is later re-broadcast
                    # it picks up its prioritisation).  Mirror that here.
                    if n_fee_delta != 0:
                        self.prioritise_transaction(tx.get_txid(), int(n_fee_delta))

            # mapDeltas tail + unbroadcast_txids.
            # FIX-76 (W120 brief-error closure for FIX-72): standalone deltas
            # — i.e. txids in mapDeltas that are NOT in the dumped tx set —
            # are restored.  Matches Core (mempool_persist.cpp:125-132).
            try:
                if offset < len(body):
                    map_count, offset = self._read_compact_size(body, offset)
                    for _ in range(map_count):
                        if offset + 32 + 8 > len(body):
                            break
                        txid_bytes = body[offset:offset + 32]
                        offset += 32
                        delta = struct.unpack_from("<q", body, offset)[0]
                        offset += 8
                        if int(delta) != 0:
                            self.prioritise_transaction(bytes(txid_bytes), int(delta))
                if offset < len(body):
                    ub_count, offset = self._read_compact_size(body, offset)
                    for _ in range(ub_count):
                        if offset + 32 > len(body):
                            break
                        offset += 32
            except Exception as e:
                logger.debug(f"Trailing mempool.dat sections skipped: {e}")

            logger.info(
                f"Loaded {loaded} mempool transactions from {filepath} "
                f"(format=v{version})"
                + (f" ({skipped} skipped)" if skipped else "")
            )
        except Exception as e:
            logger.warning(f"Failed to load mempool from {filepath}: {e}")

        # Remove the file after loading (one-shot)
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass

        return loaded

    def has_transaction(self, txid: bytes) -> bool:
        """
        Check if transaction is in mempool.

        Args:
            txid: Transaction ID to check

        Returns:
            True if transaction is in mempool
        """
        return txid in self.transactions

    def get_transaction_entry(self, txid: bytes) -> MempoolEntry | None:
        """
        Get mempool entry for a transaction.

        Args:
            txid: Transaction ID

        Returns:
            MempoolEntry or None if not found
        """
        return self.transactions.get(txid)

    # --- BIP 152 Compact Block Support ---

    def get_transaction_by_wtxid(self, wtxid: bytes) -> Transaction | None:
        """O(1) wtxid → Transaction lookup via the dual index.

        Used by BIP 331 (getpkgtxns) and the cmpctblock path.  Returns None
        if no mempool entry has the given wtxid.
        """
        txid = self.wtxid_to_txid.get(wtxid)
        if txid is None:
            return None
        entry = self.transactions.get(txid)
        return entry.tx if entry is not None else None

    def build_short_txid_map(
        self, siphash_key: bytes
    ) -> dict[int, Transaction]:
        """
        Build a map of short txid -> transaction for compact block reconstruction.

        This is called when we receive a cmpctblock message and need to match
        the 6-byte short txids against our mempool.  Iterates the dual
        ``wtxid_to_txid`` index so the inner loop is a single dict lookup
        per entry — no on-demand wtxid recomputation.

        Args:
            siphash_key: 16-byte SipHash key derived from block header + nonce

        Returns:
            Dict mapping 48-bit short txid -> Transaction.
            If two transactions collide to the same short id, the later one wins
            (Bitcoin Core handles this by nulling the entry on collision).
        """
        from ouroboros.compact_blocks import short_txid

        result: dict[int, Transaction] = {}
        for wtxid, txid in self.wtxid_to_txid.items():
            entry = self.transactions.get(txid)
            if entry is None:
                continue
            sid = short_txid(siphash_key, wtxid)
            # On collision, we could null out the entry like Bitcoin Core,
            # but for simplicity we just overwrite (caller handles missing txs)
            result[sid] = entry.tx
        return result

    def match_compact_block(
        self, short_ids: list[int], siphash_key: bytes
    ) -> tuple[list[Transaction | None], list[int]]:
        """
        Match a list of short txids against the mempool.

        Used during compact block reconstruction to find which transactions
        we already have in our mempool.  Drives the inner loop off the
        ``wtxid_to_txid`` dual index so the wtxid is read directly instead
        of being recomputed from the transaction body.

        Args:
            short_ids: List of 48-bit short txids from the cmpctblock
            siphash_key: 16-byte SipHash key

        Returns:
            (matched_txs, missing_indices) where:
            - matched_txs[i] is the Transaction for short_ids[i], or None if missing
            - missing_indices lists the indices of short_ids we couldn't find
        """
        from ouroboros.compact_blocks import short_txid

        # Build short_id -> tx via the wtxid index (no per-call wtxid hash).
        wtxid_to_tx: dict[int, Transaction] = {}
        collisions: set[int] = set()

        for wtxid, txid in self.wtxid_to_txid.items():
            entry = self.transactions.get(txid)
            if entry is None:
                continue
            sid = short_txid(siphash_key, wtxid)
            if sid in wtxid_to_tx:
                # Collision - mark both as unavailable
                collisions.add(sid)
            else:
                wtxid_to_tx[sid] = entry.tx

        # Remove collisions (like Bitcoin Core's duplicate detection)
        for sid in collisions:
            wtxid_to_tx.pop(sid, None)

        # Match each short id
        matched: list[Transaction | None] = []
        missing: list[int] = []

        for i, sid in enumerate(short_ids):
            tx = wtxid_to_tx.get(sid)
            matched.append(tx)
            if tx is None:
                missing.append(i)

        return matched, missing

    # --- Package Validation / CPFP ---

    @staticmethod
    def is_child_with_parents(txs: list[Transaction]) -> bool:
        """
        Check if the package has child-with-parents topology.

        For a valid child-with-parents package:
        - The package must have at least 2 transactions
        - The last transaction is the "child"
        - All other transactions must be direct parents of the child
          (i.e., the child must spend at least one output from each parent)

        Reference: Bitcoin Core policy/packages.cpp IsChildWithParents()
        """
        if len(txs) < 2:
            return False

        # The child is the last transaction
        child = txs[-1]

        # Collect all txids that the child spends from
        child_parent_txids: set[bytes] = set()
        for inp in child.inputs:
            child_parent_txids.add(inp.prev_txid)

        # Every transaction except the child must be a parent of the child
        for tx in txs[:-1]:
            txid = tx.get_txid()
            if txid not in child_parent_txids:
                return False

        return True

    @staticmethod
    def is_child_with_parents_tree(txs: list[Transaction]) -> bool:
        """
        Check if the package is a child-with-parents tree (no inter-parent deps).

        For a valid child-with-parents tree:
        - Must satisfy is_child_with_parents()
        - Parents cannot depend on each other (no parent spends from another parent)

        Reference: Bitcoin Core policy/packages.cpp IsChildWithParentsTree()
        """
        if not Mempool.is_child_with_parents(txs):
            return False

        # Collect all parent txids (all except the last one)
        parent_txids: set[bytes] = {tx.get_txid() for tx in txs[:-1]}

        # Check that no parent spends from another parent
        for tx in txs[:-1]:
            for inp in tx.inputs:
                if inp.prev_txid in parent_txids:
                    # This parent depends on another parent — not a tree
                    return False

        return True

    def validate_package(
        self, txs: list[Transaction], height: int
    ) -> tuple[bool, str]:
        """
        Validate and accept a package of transactions (CPFP support).

        Supports two topologies:
        1. A single transaction
        2. A child-with-parents package (1 child paying for N parents)

        The package is evaluated as a unit: individual transactions are allowed
        to fall below the minimum relay fee as long as the *package* fee rate
        meets the mempool minimum.

        Reference: Bitcoin Core validation.cpp AcceptPackage()

        Args:
            txs: List of transactions in topological order (parents before child)
            height: Current block height

        Returns:
            (success, error_message)
        """
        with self._lock:
            return self._validate_package_inner(txs, height)

    def _validate_package_inner(
        self, txs: list[Transaction], height: int
    ) -> tuple[bool, str]:
        """Unlocked implementation of validate_package."""
        if not txs:
            return False, "Empty package"

        if len(txs) > MAX_PACKAGE_COUNT:
            return False, (
                f"Package too large: {len(txs)} > {MAX_PACKAGE_COUNT}"
            )

        # Check for duplicates within the package
        seen_txids: set[bytes] = set()
        for tx in txs:
            txid = tx.get_txid()
            if txid in seen_txids:
                return False, f"Duplicate transaction in package: {txid.hex()[:16]}..."
            seen_txids.add(txid)

        # Check total weight
        total_weight = sum([tx.get_weight() for tx in txs])
        if total_weight > MAX_PACKAGE_WEIGHT:
            return False, (
                f"Package weight {total_weight} exceeds {MAX_PACKAGE_WEIGHT}"
            )

        # Check for double-spends within the package
        package_spent: set[OutPoint] = set()
        for tx in txs:
            for inp in tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                if op in package_spent:
                    return False, (
                        f"Double-spend within package: "
                        f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout}"
                    )
                package_spent.add(op)

        # Verify topological order: every input that references a package
        # tx must reference one that appeared earlier.
        txid_to_pos = {tx.get_txid(): i for i, tx in enumerate(txs)}
        for i, tx in enumerate(txs):
            for inp in tx.inputs:
                parent_pos = txid_to_pos.get(inp.prev_txid)
                if parent_pos is not None and parent_pos >= i:
                    return False, (
                        "Package not in topological order: "
                        f"tx at position {i} spends output of tx at position {parent_pos}"
                    )

        # Check child-with-parents topology for multi-tx packages
        # Reference: Bitcoin Core validation.cpp AcceptPackage()
        if len(txs) > 1:
            if not self.is_child_with_parents(txs):
                return False, "package-not-child-with-parents"
            if not self.is_child_with_parents_tree(txs):
                return False, (
                    "package topology disallowed: parents depend on each other"
                )

        # Compute per-transaction fees BEFORE ephemeral dust checks
        # We need individual fees to enforce the 0-fee requirement for dust parents.
        # Build a temporary UTXO view that includes outputs created by
        # earlier transactions in the package.
        package_outputs: dict[OutPoint, int] = {}  # (txid, vout) → value
        tx_fees: dict[bytes, int] = {}  # txid → fee

        for tx in txs:
            txid = tx.get_txid()
            # Sum inputs — from chain UTXO set, mempool, or package
            total_input = 0
            for inp in tx.inputs:
                op: OutPoint = (inp.prev_txid, inp.prev_vout)
                if op in package_outputs:
                    total_input += package_outputs[op]
                else:
                    parent_entry = self.transactions.get(inp.prev_txid)
                    if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                        total_input += parent_entry.tx.outputs[inp.prev_vout].value
                    else:
                        utxo = self.validator.db.get_utxo(inp.prev_txid, inp.prev_vout)
                        if utxo:
                            total_input += utxo['value']
                        else:
                            return False, (
                                f"UTXO not found for package tx: "
                                f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout}"
                            )

            total_output = sum(out.value for out in tx.outputs)
            fee = total_input - total_output
            if fee < 0:
                return False, f"Negative fee in package tx {txid.hex()[:16]}..."
            tx_fees[txid] = fee

            # Register outputs for children in the package
            for vout, out in enumerate(tx.outputs):
                package_outputs[(txid, vout)] = out.value

        # Ephemeral dust policy checks (Bitcoin Core policy/ephemeral_policy.cpp)
        # For any tx with dust outputs:
        # 1. At most 1 dust output per transaction
        # 2. Dust tx must have 0 fee (child provides all fees via CPFP)
        # 3. Dust output must be P2A or standard type
        # 4. All dust outputs must be spent by child in same package
        for tx in txs:
            dust_indices = _has_ephemeral_dust(tx)
            if not dust_indices:
                continue

            txid = tx.get_txid()
            fee = tx_fees.get(txid, 0)

            # Check ephemeral dust policy (max 1 dust, 0-fee, standard type)
            ok, err = _check_ephemeral_dust(tx, fee)
            if not ok:
                return False, f"ephemeral dust policy: {err}"

            # All dust outputs must be spent by a child in the package
            for dust_vout in dust_indices:
                dust_outpoint: OutPoint = (txid, dust_vout)
                if dust_outpoint not in package_spent:
                    return False, (
                        f"tx {txid.hex()[:16]}... has unspent ephemeral "
                        f"dust output at index {dust_vout}"
                    )

        # TRUC (v3) policy checks for packages
        # Reference: Bitcoin Core policy/truc_policy.cpp PackageTRUCChecks()
        truc_ok, truc_err = self._check_package_truc_policy(txs)
        if not truc_ok:
            return False, truc_err

        # Validate each transaction (consensus checks only)
        for tx in txs:
            txid = tx.get_txid()
            if txid in self.transactions:
                return False, f"Transaction {txid.hex()[:16]}... already in mempool"

        # Check conflicts with existing mempool (any double-spend)
        for tx in txs:
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_vout)
                if op in self.spent_outputs:
                    return False, (
                        f"Package conflicts with mempool: "
                        f"{inp.prev_txid.hex()[:16]}...:{inp.prev_vout} already spent"
                    )

        # Calculate total fees and size using pre-computed per-tx fees
        total_fees = sum(tx_fees.values())
        total_size = sum(len(tx.serialize()) for tx in txs)

        # Package fee rate check (CPFP: package rate must meet minimum)
        package_fee_rate = total_fees / total_size if total_size > 0 else 0
        min_relay = (total_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        if total_fees < min_relay:
            return False, (
                f"Package fee rate too low: {package_fee_rate:.2f} sat/vB "
                f"(need {DEFAULT_MIN_RELAY_TX_FEE / 1000:.2f} sat/vB)"
            )

        # Consensus-validate each transaction.
        # BIP-113: use MTP of current tip as locktime cutoff (same as
        # AcceptToMemoryPool in Core validation.cpp:164).
        try:
            pkg_mtp: int = self.validator.db.get_median_time_past(height) or 0
        except Exception:
            pkg_mtp = 0
        # Build a rolling intra_block_utxos view of package parent outputs so
        # that child transactions can find outputs that are not yet in the UTXO
        # DB.  Mirrors Core AcceptMultipleTransactions which builds a package
        # UTXO view (CCoinsViewMemPool over the package) before calling
        # AcceptToMemoryPool for each transaction.  Txs are in topological
        # order (enforced above), so accumulating outputs tx-by-tx is safe.
        pkg_utxo_view: dict = {}
        for tx in txs:
            txid = tx.get_txid()
            valid, error = self.validator.validate_transaction(
                tx, height, pkg_mtp,
                intra_block_utxos=pkg_utxo_view if pkg_utxo_view else None,
            )
            if not valid:
                return False, f"Package tx {txid.hex()[:16]}... invalid: {error}"
            # Register this tx's outputs so subsequent (child) txs can find them.
            for vout_idx, out in enumerate(tx.outputs):
                pkg_utxo_view[(txid, vout_idx)] = {
                    'txid': txid,
                    'vout': vout_idx,
                    'value': out.value,
                    'script_pubkey': out.script_pubkey,
                    'height': height,
                    'is_coinbase': False,
                }

        # All checks passed — add transactions in topological order.
        # Use pre-computed per-tx fees; skip per-tx minimum fee check
        # (package rate already validated above).
        added_txids: list[bytes] = []
        ephemeral_parents: set[bytes] = set()  # Track parents with ephemeral dust

        for tx in txs:
            txid = tx.get_txid()
            tx_size = len(tx.serialize())

            # Compute direct parents (mempool txs this tx spends from)
            direct_parents: set[bytes] = set()
            for inp in tx.inputs:
                if inp.prev_txid in self.transactions:
                    direct_parents.add(inp.prev_txid)

            # Use pre-computed fee from earlier validation
            fee = tx_fees.get(txid, 0)
            fee_rate = fee / tx_size if tx_size > 0 else 0

            # Track if this is an ephemeral dust parent
            if _has_ephemeral_dust(tx):
                ephemeral_parents.add(txid)

            ancestors = self._get_ancestors(tx)
            ancestor_size = sum(
                self.transactions[a].size
                for a in ancestors if a in self.transactions
            )

            has_dust = txid in ephemeral_parents
            entry = MempoolEntry(
                tx=tx,
                fee=fee,
                fee_rate=fee_rate,
                size=tx_size,
                time_added=time.time(),
                height_added=height,
                ancestor_count=len(ancestors) + 1,
                ancestor_size=ancestor_size + tx_size,
                parents=direct_parents,
                children=set(),
                has_ephemeral_dust=has_dust,
            )
            self.transactions[txid] = entry
            self.current_size += tx_size

            for inp in tx.inputs:
                self.spent_outputs.add((inp.prev_txid, inp.prev_vout))

            self._insert_sorted_by_fee_rate(txid, fee_rate)

            # Update parent entries to add this txid as a child
            # Also track ephemeral dust relationships
            for parent_txid in direct_parents:
                if parent_txid in self.transactions:
                    parent_entry = self.transactions[parent_txid]
                    parent_entry.children.add(txid)
                    # If parent has ephemeral dust, mark this child as spending it
                    if parent_entry.has_ephemeral_dust:
                        parent_entry.ephemeral_child = txid

            # Update ancestor descendant counts
            for a_txid in ancestors:
                if a_txid in self.transactions:
                    self.transactions[a_txid].descendant_count += 1
                    self.transactions[a_txid].descendant_size += tx_size

            added_txids.append(txid)

        logger.info(
            f"Accepted package of {len(added_txids)} txs "
            f"(total fee {total_fees}, package rate {package_fee_rate:.2f} sat/vB)"
        )

        # Resolve any orphans that may be waiting on these transactions
        for txid in added_txids:
            self._resolve_orphans(txid, height)

        return True, ""
