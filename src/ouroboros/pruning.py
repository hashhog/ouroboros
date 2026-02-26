"""
Block Pruning — discard old block data to save disk space.

After a block has been fully validated and its UTXO effects applied,
the raw block data is no longer needed for ongoing consensus.  This
module implements a ``BlockPruner`` that keeps only the most recent
*N* blocks (or limits total storage to a target size) while
preserving the UTXO set, block index, and headers.

Pruning modes (following Bitcoin Core):
- ``target_size_mb``: prune block files when total exceeds this
- ``keep_blocks``: always keep at least the last N blocks

The node is still a full validating node — it validated every block
before pruning.  However pruned blocks cannot be served to peers.

Reference: bitcoin/src/node/blockstorage.cpp — PruneOneBlockFile()
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class PruneRecord:
    """Tracks which block heights have been pruned."""
    pruned_heights: Set[int] = field(default_factory=set)
    lowest_unpruned: int = 0
    total_pruned_bytes: int = 0


class BlockPruner:
    """
    Manages block data pruning.

    Block data is stored as individual files under
    ``{data_dir}/blocks/{height}.dat``.  When pruning is enabled the
    pruner periodically removes old block files while keeping the
    most recent ``keep_blocks`` blocks.

    The pruner persists its state in ``{data_dir}/prune_state.json``
    so it can resume correctly across restarts.
    """

    MIN_KEEP_BLOCKS = 288  # ~2 days of blocks (Bitcoin Core minimum)

    def __init__(
        self,
        data_dir: str,
        target_size_mb: int = 550,
        keep_blocks: int = 288,
    ):
        self.data_dir = Path(data_dir)
        self.blocks_dir = self.data_dir / "blocks"
        self.state_path = self.data_dir / "prune_state.json"
        self.target_size = target_size_mb * 1_000_000
        self.keep_blocks = max(keep_blocks, self.MIN_KEEP_BLOCKS)
        self.record = PruneRecord()
        self._load_state()

    # ── state persistence ─────────────────────────────────────────

    def _load_state(self) -> None:
        if self.state_path.exists():
            with open(self.state_path) as f:
                data = json.load(f)
            self.record.pruned_heights = set(data.get("pruned_heights", []))
            self.record.lowest_unpruned = data.get("lowest_unpruned", 0)
            self.record.total_pruned_bytes = data.get("total_pruned_bytes", 0)

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pruned_heights": sorted(self.record.pruned_heights),
            "lowest_unpruned": self.record.lowest_unpruned,
            "total_pruned_bytes": self.record.total_pruned_bytes,
        }
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(payload, f)
        tmp.rename(self.state_path)

    # ── size accounting ───────────────────────────────────────────

    def get_blocks_size(self) -> int:
        """Total size of all block data files in bytes."""
        if not self.blocks_dir.exists():
            return 0
        total = 0
        for entry in self.blocks_dir.iterdir():
            if entry.is_file() and entry.suffix == ".dat":
                total += entry.stat().st_size
        return total

    def is_pruned(self, height: int) -> bool:
        return height in self.record.pruned_heights

    # ── pruning ───────────────────────────────────────────────────

    def prune_blocks(self, current_height: int) -> int:
        """
        Prune old blocks up to ``current_height - keep_blocks``.

        Returns the number of block files removed.
        """
        if current_height <= self.keep_blocks:
            return 0

        max_prune_height = current_height - self.keep_blocks
        removed = 0

        for height in range(self.record.lowest_unpruned, max_prune_height + 1):
            if height in self.record.pruned_heights:
                continue
            block_path = self.blocks_dir / f"{height}.dat"
            if block_path.exists():
                size = block_path.stat().st_size
                block_path.unlink()
                self.record.total_pruned_bytes += size
                removed += 1
            self.record.pruned_heights.add(height)

        self.record.lowest_unpruned = max_prune_height + 1
        if removed > 0:
            self._save_state()
            logger.info(
                f"Pruned {removed} blocks (heights < {max_prune_height + 1}), "
                f"total pruned: {self.record.total_pruned_bytes / 1e6:.1f} MB"
            )
        return removed

    def prune_to_target(self, current_height: int) -> int:
        """
        Prune oldest blocks until total storage is below ``target_size``.

        Returns the number of block files removed.
        """
        current_size = self.get_blocks_size()
        if current_size <= self.target_size:
            return 0

        max_prune_height = current_height - self.keep_blocks
        removed = 0
        height = self.record.lowest_unpruned

        while current_size > self.target_size and height <= max_prune_height:
            if height not in self.record.pruned_heights:
                block_path = self.blocks_dir / f"{height}.dat"
                if block_path.exists():
                    size = block_path.stat().st_size
                    block_path.unlink()
                    current_size -= size
                    self.record.total_pruned_bytes += size
                    removed += 1
                self.record.pruned_heights.add(height)
            height += 1

        self.record.lowest_unpruned = height
        if removed > 0:
            self._save_state()
            logger.info(
                f"Pruned {removed} blocks to target "
                f"({current_size / 1e6:.1f} MB remaining)"
            )
        return removed

    def get_prune_info(self) -> Dict:
        return {
            "pruned": len(self.record.pruned_heights) > 0,
            "pruned_blocks": len(self.record.pruned_heights),
            "lowest_unpruned": self.record.lowest_unpruned,
            "total_pruned_bytes": self.record.total_pruned_bytes,
            "blocks_size": self.get_blocks_size(),
            "target_size": self.target_size,
            "keep_blocks": self.keep_blocks,
        }
