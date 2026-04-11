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


class BlockPruner:
    """
    Manages block data pruning via the Rust flat file storage layer.

    Block data is stored in blk*.dat files, with corresponding undo data
    in rev*.dat files.  When pruning, entire files are deleted once all
    their blocks are below the prune threshold.  The block index (headers
    and metadata) is preserved, so the node can still answer header queries.

    This mirrors Bitcoin Core's behaviour where ``CBlockIndex`` records
    survive pruning but the raw ``blk*.dat`` data is removed.
    """

    MIN_KEEP_BLOCKS = 288  # ~2 days of blocks
    MIN_TARGET_MB = 550    # Bitcoin Core -prune minimum

    def __init__(
        self,
        block_store: Any = None,
        target_size_mb: int = 550,
        keep_blocks: int = 288,
        *,
        db: Any = None,
    ):
        """
        Create a block pruner.

        Args:
            block_store: PyBlockStore instance (from sync module).
                         Also accepted as keyword argument ``db`` for compatibility.
            target_size_mb: Target disk usage in MB (minimum 550)
            keep_blocks: Minimum blocks to keep above prune height (minimum 288)
        """
        if db is not None and block_store is None:
            block_store = db
        self.block_store = block_store
        self.target_size = max(target_size_mb, self.MIN_TARGET_MB) * 1_000_000
        self.keep_blocks = max(keep_blocks, self.MIN_KEEP_BLOCKS)

    @property
    def prune_height(self) -> int:
        """Lowest block height whose body is still available."""
        return self.block_store.get_prune_height()

    def is_pruned(self, height: int) -> bool:
        """True when the block body at *height* has been removed."""
        return not self.block_store.has_block_data_at_height(height)

    def get_stats(self) -> PruneStats:
        """Get current pruning statistics."""
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
        Prune old blocks to meet the target size.

        Deletes block files whose highest block is at least ``keep_blocks``
        below ``current_height``, until disk usage is below ``target_size``.

        Args:
            current_height: Current best block height

        Returns:
            Tuple of (files_pruned, bytes_freed).
        """
        if current_height <= self.keep_blocks:
            return 0, 0

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
            Actual height pruned to (may be less than target due to keep_blocks).
        """
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

    def prune_to_target(self, current_height: int) -> tuple[int, int]:
        """
        Prune oldest blocks until storage is below ``target_size``.

        This is an alias for ``prune_blocks`` for backwards compatibility.

        Args:
            current_height: Current best block height

        Returns:
            Tuple of (files_pruned, bytes_freed).
        """
        return self.prune_blocks(current_height)

    def get_prune_info(self) -> dict[str, Any]:
        """Return a summary dict suitable for RPC responses."""
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
