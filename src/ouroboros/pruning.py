"""
Block Pruning — discard old block data to save disk space.

After a block has been fully validated and its UTXO effects applied,
the raw block data is no longer needed for ongoing consensus.  This
module implements a ``BlockPruner`` that deletes block bodies from the
RocksDB ``BLOCKS_CF`` column family while preserving the block index
(height → hash mapping), headers, and UTXO set.

Pruning modes (following Bitcoin Core):
- ``target_size_mb``: prune block data when total exceeds this
- ``keep_blocks``: always keep at least the last N blocks

The node is still a full validating node — it validated every block
before pruning.  However pruned blocks cannot be served to peers.

Reference: bitcoin/src/node/blockstorage.cpp — PruneOneBlockFile()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class BlockPruner:
    """
    Manages block data pruning via the Rust storage layer (RocksDB).

    Block bodies are stored in the ``blocks`` column family keyed by
    block hash.  When pruning, we delete the body but keep the block
    index entry (height → hash + metadata) so the node can still serve
    headers and knows which heights existed.

    This mirrors Bitcoin Core's behaviour where ``CBlockIndex`` records
    survive pruning but the raw ``blk*.dat`` data is removed.
    """

    MIN_KEEP_BLOCKS = 288  # ~2 days of blocks (Bitcoin Core minimum)
    MIN_TARGET_MB = 550     # Bitcoin Core -prune minimum

    def __init__(
        self,
        db: Any,
        target_size_mb: int = 550,
        keep_blocks: int = 288,
    ):
        """
        Args:
            db: A ``PyBlockchainDB`` (Rust-backed) or compatible object
                that exposes ``prune_blocks_range``, ``get_prune_height``,
                ``has_block_data``, ``estimate_blocks_size``, and
                ``get_best_block``.
            target_size_mb: Prune when total block data exceeds this (MB).
            keep_blocks: Always keep at least this many recent blocks.
        """
        self.db = db
        self.target_size = target_size_mb * 1_000_000
        self.keep_blocks = max(keep_blocks, self.MIN_KEEP_BLOCKS)

    @property
    def prune_height(self) -> int:
        """Lowest block height whose body is still available."""
        return self.db.get_prune_height()

    def is_pruned(self, height: int) -> bool:
        """True when the block body at *height* has been removed."""
        return not self.db.has_block_data(height)

    def prune_blocks(self, current_height: int) -> int:
        """
        Prune old blocks up to ``current_height - keep_blocks``.

        Returns the number of block bodies removed.
        """
        if current_height <= self.keep_blocks:
            return 0

        from_height = self.db.get_prune_height()
        to_height = current_height - self.keep_blocks

        if from_height > to_height:
            return 0

        removed = self.db.prune_blocks_range(from_height, to_height)
        if removed > 0:
            logger.info(
                "Pruned %d block(s) (heights %d–%d)",
                removed, from_height, to_height,
            )
        return removed

    def prune_to_target(self, current_height: int) -> int:
        """
        Prune oldest blocks until total block storage is below
        ``target_size``.

        Returns the number of block bodies removed.
        """
        current_size = self.db.estimate_blocks_size()
        if current_size <= self.target_size:
            return 0

        max_prune_height = current_height - self.keep_blocks
        start_height = self.db.get_prune_height()
        total_removed = 0

        height = start_height
        while current_size > self.target_size and height <= max_prune_height:
            if self.db.has_block_data(height):
                self.db.prune_blocks_range(height, height)
                total_removed += 1
                current_size = self.db.estimate_blocks_size()
            height += 1

        if total_removed > 0:
            remaining_mb = current_size / 1e6
            logger.info(
                "Pruned %d block(s) to target (%.1f MB remaining)",
                total_removed, remaining_mb,
            )
        return total_removed

    def get_prune_info(self) -> Dict[str, Any]:
        """Return a summary dict suitable for RPC responses."""
        prune_h = self.db.get_prune_height()
        blocks_size = self.db.estimate_blocks_size()
        return {
            "pruned": prune_h > 0,
            "prune_height": prune_h,
            "blocks_size": blocks_size,
            "target_size": self.target_size,
            "keep_blocks": self.keep_blocks,
        }
