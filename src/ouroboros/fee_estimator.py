"""
Fee estimation based on recent block fee rate statistics.

Tracks fee rates from the most recent N confirmed blocks and returns
percentile-based estimates for target confirmation windows.

Bitcoin Core uses exponential-decay fee rate buckets (CBlockPolicyEstimator
in policy/fees.cpp). This is a simpler percentile approach that observes
which fee rates actually made it into blocks and uses that distribution
to recommend rates for a given confirmation target.
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_BLOCK_HISTORY = 144


@dataclass
class BlockFeeData:
    """Fee rate statistics for a single confirmed block."""
    height: int
    fee_rates: List[float]
    median_fee_rate: float
    min_fee_rate: float


class FeeEstimator:
    """
    Estimates required fee rates based on observed fee rates in recent
    confirmed blocks.

    Fee data comes from mempool entries: when a block confirms a transaction
    that was in our mempool, we know its exact fee and vsize.
    """

    def __init__(self, max_history: int = MAX_BLOCK_HISTORY):
        self.max_history = max_history
        self.block_history: deque[BlockFeeData] = deque(maxlen=max_history)

    def process_block(self, block, height: int, mempool=None) -> None:
        """
        Record fee rate data from a newly confirmed block.

        For each non-coinbase transaction that was in our mempool, record
        its fee rate. Transactions we never saw in our mempool are skipped
        (we don't know their fee).

        Args:
            block: Block object with .transactions list
            height: Block height
            mempool: Mempool instance to look up fee data
        """
        fee_rates: List[float] = []

        for tx in block.transactions:
            if tx.is_coinbase:
                continue

            if mempool is not None:
                entry = mempool.get_transaction_entry(tx.get_txid())
                if entry is not None and entry.fee > 0:
                    vsize = entry.size if entry.size > 0 else 1
                    fee_rates.append(entry.fee / vsize)

        if not fee_rates:
            return

        fee_rates.sort()
        median = fee_rates[len(fee_rates) // 2]
        self.block_history.append(BlockFeeData(
            height=height,
            fee_rates=fee_rates,
            median_fee_rate=median,
            min_fee_rate=fee_rates[0],
        ))
        logger.debug(
            f"Fee estimator: block {height} had {len(fee_rates)} txs "
            f"with median fee rate {median:.1f} sat/vB"
        )

    def estimate_fee(self, conf_target: int = 6) -> Optional[float]:
        """
        Estimate fee rate (sat/vB) for confirmation within conf_target blocks.

        Strategy mirrors Bitcoin Core's buckets at a coarse level:
        - conf_target 1-2:  90th percentile (high priority)
        - conf_target 3-6:  50th percentile (normal)
        - conf_target 7-25: 25th percentile (low priority)
        - conf_target 25+:  10th percentile (economy)

        Returns None if insufficient data (< 3 blocks observed).
        """
        if len(self.block_history) < 3:
            return None

        sample_depth = min(len(self.block_history), max(conf_target * 2, 6))

        all_rates: List[float] = []
        for block_data in list(self.block_history)[-sample_depth:]:
            all_rates.extend(block_data.fee_rates)

        if not all_rates:
            return None

        all_rates.sort()

        if conf_target <= 2:
            percentile = 0.90
        elif conf_target <= 6:
            percentile = 0.50
        elif conf_target <= 25:
            percentile = 0.25
        else:
            percentile = 0.10

        idx = min(int(len(all_rates) * percentile), len(all_rates) - 1)
        return max(all_rates[idx], 1.0)

    def estimate_fee_per_kb(self, conf_target: int = 6) -> Optional[float]:
        """Return fee estimate in BTC/kB (Bitcoin Core RPC format)."""
        rate = self.estimate_fee(conf_target)
        if rate is None:
            return None
        return rate * 1000 / 1e8

    def get_fee_summary(self) -> Dict:
        """Return summary statistics for diagnostics."""
        if not self.block_history:
            return {"blocks_tracked": 0}

        medians = [b.median_fee_rate for b in self.block_history]
        return {
            "blocks_tracked": len(self.block_history),
            "oldest_height": self.block_history[0].height,
            "newest_height": self.block_history[-1].height,
            "median_fee_rate": sorted(medians)[len(medians) // 2],
            "min_fee_rate": min(b.min_fee_rate for b in self.block_history),
        }
