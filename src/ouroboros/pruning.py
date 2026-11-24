"""
Block Pruning — delete old block/undo files to save disk space.

After a block has been fully validated and its UTXO effects applied,
the raw block data is no longer needed for ongoing consensus.  This
module implements a ``BlockPruner`` that deletes blk*.dat and rev*.dat
files while preserving the block index (headers + metadata) and UTXO set.

Pruning modes:
- ``target_size_mb``: prune block files when total exceeds this
- ``keep_blocks``: always keep at least the last N blocks (min 288)

The node remains a full validating node — it validated every block
before pruning.  However pruned blocks cannot be served to peers.

Reference: bitcoin/src/node/blockstorage.cpp — PruneOneBlockFile(), FindFilesToPrune()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PruneStats:
    """Statistics about block storage and pruning state."""

    total_files: int
    """Total number of block files ever created."""

    pruned_files: int
    """Number of files that have been pruned."""

    data_bytes: int
    """Total bytes of block data on disk."""

    undo_bytes: int
    """Total bytes of undo data on disk."""

    prune_height: int
    """Lowest height with available block data."""

    @property
    def total_bytes(self) -> int:
        """Total bytes on disk (block + undo data)."""
        return self.data_bytes + self.undo_bytes

    @property
    def total_mb(self) -> float:
        """Total megabytes on disk."""
        return self.total_bytes / 1_000_000

    @property
    def is_pruned(self) -> bool:
        """True if any pruning has occurred."""
        return self.pruned_files > 0 or self.prune_height > 0


# Core chainparams nPruneAfterHeight: the automatic pruner and
# pruneblockchain do nothing until the active chain is taller than this.
PRUNE_AFTER_HEIGHT = {
    "mainnet": 100_000,
    "testnet": 1_000,
    "testnet3": 1_000,
    "testnet4": 1_000,
    "signet": 1_000,
    "regtest": 1_000,
}

MIB = 1024 * 1024


class BlockPruner:
    """
    Block-data pruning, over either storage backend.

    The node keeps blocks in RocksDB (``BlockchainDatabase`` / ``PyBlockchainDB``:
    bodies in BLOCKS_CF, undo records in UNDO_CF) and that is what ``Node``
    hands this class.  The flat-file ``PyBlockStore`` (blk/rev files) is
    still accepted.  Either way the block index (headers and metadata)
    survives pruning, so the node still answers header queries, serves
    ``getheaders`` and resolves the retarget ancestor.

    This mirrors Bitcoin Core's behaviour where ``CBlockIndex`` records
    survive pruning but the raw ``blk*.dat`` / ``rev*.dat`` data is removed.

    Before this class learned the chain-DB backend, ``Node`` passed it a
    ``BlockchainDatabase``, which has none of the flat-file methods
    (``prune_to_target``, ``get_prune_stats`` ...): every automatic pass
    raised AttributeError, the node logged it at DEBUG, and ``-prune``
    deleted nothing.
    """

    MIN_KEEP_BLOCKS = 288  # Core MIN_BLOCKS_TO_KEEP (validation.h)
    MIN_TARGET_MB = 550    # Core MIN_DISK_SPACE_FOR_BLOCK_FILES / 1 MiB

    def __init__(
        self,
        block_store: Any = None,
        target_size_mb: int = 550,
        keep_blocks: int = 288,
        *,
        db: Any = None,
        network: str | None = None,
    ):
        """
        Create a block pruner.

        Args:
            block_store: ``BlockchainDatabase`` (what the node uses) or a
                         flat-file ``PyBlockStore``.
                         Also accepted as keyword argument ``db`` for compatibility.
            target_size_mb: Target disk usage in MiB, as Core's ``-prune=N``
                            (``N * 1024 * 1024`` bytes). Special values:
                            ``1`` → manual mode (Bitcoin Core init.cpp:524 /
                            blockmanager_args.cpp:27): node is in prune mode
                            (NODE_NETWORK_LIMITED, getblockchaininfo.pruned=true)
                            but the automatic prune trigger does not fire; only
                            ``prune_to_height`` (driven by the pruneblockchain
                            RPC) deletes data. Any other value <550 is silently
                            promoted to 550 for the auto-prune target.
            keep_blocks: Minimum blocks to keep above prune height (minimum 288)
            network: Chain name; selects Core's ``nPruneAfterHeight``.  None
                     (the default) applies no such floor.
        """
        if db is not None and block_store is None:
            block_store = db
        self.block_store = block_store
        # `-prune=1` manual-only sentinel (Core PRUNE_TARGET_MANUAL,
        # node/blockstorage.h:408). Maps to "auto-prune off; manual via RPC".
        self.manual = target_size_mb == 1
        self.target_size = max(target_size_mb, self.MIN_TARGET_MB) * MIB
        self.keep_blocks = max(keep_blocks, self.MIN_KEEP_BLOCKS)
        self.prune_after_height = PRUNE_AFTER_HEIGHT.get(network or "", 0)
        # Bytes of block + undo data the last automatic pass left stored
        # (chain-DB backend only; None before the first pass).
        self.retained_bytes: int | None = None
        # True when the last automatic step stopped at its bound with
        # prunable blocks left: the caller runs another step after releasing
        # the chain lock (chain-DB backend only).
        self.pending = False

    @property
    def _chain_db(self) -> bool:
        """True for the RocksDB chain-DB backend (what the node runs on)."""
        return hasattr(self.block_store, "prune_block_data_to_target")

    @property
    def prune_height(self) -> int:
        """Lowest block height whose body is still available."""
        return self.block_store.get_prune_height()

    def is_pruned(self, height: int) -> bool:
        """True when the block body at *height* has been removed."""
        if self._chain_db:
            return not self.block_store.has_block_data(height)
        return not self.block_store.has_block_data_at_height(height)

    def get_stats(self) -> PruneStats:
        """Get current pruning statistics."""
        if self._chain_db:
            prune_h = self.prune_height
            return PruneStats(
                total_files=0,
                pruned_files=prune_h,  # heights 0 .. prune_h-1
                data_bytes=self.retained_bytes or 0,
                undo_bytes=0,  # counted in data_bytes
                prune_height=prune_h,
            )
        total_files, pruned_files, data_bytes, undo_bytes, prune_h = (
            self.block_store.get_prune_stats()
        )
        return PruneStats(
            total_files=total_files,
            pruned_files=pruned_files,
            data_bytes=data_bytes,
            undo_bytes=undo_bytes,
            prune_height=prune_h,
        )

    def prune_blocks(self, current_height: int) -> tuple[int, int]:
        """
        Prune old blocks to meet the target size (Core ``FindFilesToPrune``).

        Deletes the data of blocks more than ``keep_blocks`` below
        ``current_height`` until the stored block data fits in
        ``target_size``.  Nothing happens until the chain is taller than
        the network's ``nPruneAfterHeight``.
        In `-prune=1` manual mode this is a no-op — only ``prune_to_height``
        (RPC-driven) may delete data, matching Bitcoin Core's
        ``PRUNE_TARGET_MANUAL`` sentinel behavior in
        ``BlockManager::FindFilesToPrune``.

        Args:
            current_height: Current best block height

        Returns:
            Chain DB: ``(blocks_pruned, bytes_retained)``: the bytes of
            block + undo data still stored after the pass.
            Flat-file store: ``(files_pruned, bytes_freed)``.
        """
        if self.manual:
            return 0, 0
        if current_height <= self.keep_blocks:
            return 0, 0
        if current_height <= self.prune_after_height:
            return 0, 0

        if self._chain_db:
            pruned, retained, self.pending = self.block_store.prune_block_data_to_target(
                current_height, self.target_size, self.keep_blocks
            )
            self.retained_bytes = retained
            if pruned > 0:
                logger.info(
                    "Pruned the data of %d block(s); %.1f MiB of block data "
                    "kept (target %.1f MiB, prune height now %d)",
                    pruned,
                    retained / MIB,
                    self.target_size / MIB,
                    self.prune_height,
                )
            return pruned, retained

        files_pruned, bytes_freed = self.block_store.prune_to_target(
            current_height, self.target_size
        )

        if files_pruned > 0:
            logger.info(
                "Pruned %d file(s), freed %.1f MB",
                files_pruned,
                bytes_freed / 1_000_000,
            )

        return files_pruned, bytes_freed

    def prune_to_height(self, target_height: int, current_height: int) -> int:
        """
        Prune blocks up to a specific height (for pruneblockchain RPC).

        Args:
            target_height: Target height to prune up to
            current_height: Current best block height

        Returns:
            Chain DB: the height of the highest pruned block, or -1 when no
            block has been pruned (Core ``GetPruneHeight().value_or(-1)``).
            Flat-file store: actual height pruned to (0 when none).
        """
        if self._chain_db:
            while True:
                highest, more = self.prune_to_height_step(target_height, current_height)
                if not more:
                    return highest

        if current_height <= self.keep_blocks:
            return 0

        max_prune_height = current_height - self.keep_blocks
        actual_target = min(target_height, max_prune_height)

        if actual_target <= 0:
            return 0

        files_pruned, bytes_freed, final_height = self.block_store.prune_to_height(
            actual_target, current_height
        )

        if files_pruned > 0:
            logger.info(
                "Manual prune: %d file(s), %.1f MB freed, up to height %d",
                files_pruned,
                bytes_freed / 1_000_000,
                final_height,
            )

        return final_height

    def prune_to_height_step(
        self, target_height: int, current_height: int
    ) -> tuple[int, bool]:
        """One bounded step of ``prune_to_height`` (chain-DB backend), for a
        caller that releases the chain lock between steps (pruneblockchain).
        Returns ``(highest_pruned_height or -1, more)``."""
        if not self._chain_db:
            return self.prune_to_height(target_height, current_height), False
        if target_height < 0:
            return self._highest_pruned(), False
        _, highest, more = self.block_store.prune_block_data_to_height(
            target_height, current_height, self.keep_blocks
        )
        if highest is not None and not more:
            logger.info("Manual prune: block data pruned up to height %d", highest)
        return (-1 if highest is None else highest), more

    def _highest_pruned(self) -> int:
        h = self.prune_height
        return h - 1 if h > 0 else -1

    def prune_to_target(self, current_height: int) -> tuple[int, int]:
        """
        Prune oldest blocks until storage is below ``target_size``.

        This is an alias for ``prune_blocks`` for backwards compatibility.

        Args:
            current_height: Current best block height

        Returns:
            What ``prune_blocks`` returns.
        """
        return self.prune_blocks(current_height)

    def core_info(self) -> dict[str, Any]:
        """The prune fields of Core's ``getblockchaininfo`` (rpc/blockchain.cpp):
        ``pruneheight`` (the first block whose data is kept, 0 when none
        was pruned), ``automatic_pruning`` and, only when automatic,
        ``prune_target_size`` in bytes."""
        info: dict[str, Any] = {
            "pruneheight": self.prune_height,
            "automatic_pruning": not self.manual,
        }
        if not self.manual:
            info["prune_target_size"] = self.target_size
        return info

    def get_prune_info(self) -> dict[str, Any]:
        """Return a summary dict of the pruner's own state (diagnostics)."""
        stats = self.get_stats()
        return {
            "pruned": stats.is_pruned,
            "prune_height": stats.prune_height,
            "pruned_files": stats.pruned_files,
            "total_files": stats.total_files,
            "blocks_size": stats.data_bytes,
            "undo_size": stats.undo_bytes,
            "size_on_disk": stats.total_bytes,
            "target_size": self.target_size,
            "keep_blocks": self.keep_blocks,
        }


class FilePruner:
    """
    Low-level file-based pruning operations.

    This class provides direct access to flat file pruning without
    requiring a full BlockPruner setup.  Used internally and for
    testing.
    """

    def __init__(self, block_store: Any):
        self.block_store = block_store

    def find_files_to_prune(
        self,
        last_block_can_prune: int,
        min_block_to_prune: int = 0,
        target_bytes: int = 0,
    ) -> list:
        """
        Find block files eligible for pruning.

        Args:
            last_block_can_prune: Highest block height that can be pruned
            min_block_to_prune: Lowest block height that can be pruned
            target_bytes: Target disk usage (0 = prune all eligible)

        Returns:
            List of file numbers that can be pruned.
        """
        return self.block_store.find_files_to_prune(
            last_block_can_prune, min_block_to_prune, target_bytes
        )

    def calculate_current_usage(self) -> int:
        """Calculate total disk usage of all block and undo files."""
        return self.block_store.calculate_current_usage()

    def get_file_info(self, file_num: int) -> dict[str, Any] | None:
        """
        Get info about a specific block file.

        Returns:
            Dict with keys: num_blocks, size, undo_size, height_first,
            height_last, time_first, time_last.  Or None if file doesn't exist.
        """
        info = self.block_store.get_file_info(file_num)
        if info is None:
            return None

        num_blocks, size, undo_size, height_first, height_last, time_first, time_last = info
        return {
            "num_blocks": num_blocks,
            "size": size,
            "undo_size": undo_size,
            "height_first": height_first,
            "height_last": height_last,
            "time_first": time_first,
            "time_last": time_last,
        }
