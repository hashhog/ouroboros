"""
Fee estimation using exponential-decay fee rate buckets.

Modelled on Bitcoin Core's ``CBlockPolicyEstimator`` (``policy/fees.cpp``).

The estimator maintains ~40 fee-rate *buckets* on a logarithmic scale
(1 – 10 000 sat/vB).  For every confirmed transaction whose fee we know
(because it was in our mempool), the bucket corresponding to its fee rate
is updated:

* ``confirmed[bucket][target]`` is incremented when the tx confirmed
  within *target* blocks.
* ``total[bucket][target]`` is incremented for every target from 1 up to
  the actual number of blocks the tx waited – reflecting that it was
  *unconfirmed* for those shorter windows.

All counters are subjected to an exponential decay (factor 0.998 per
block), so recent data naturally outweighs stale observations.

To produce an estimate for a given confirmation target *T* the estimator
finds the lowest bucket where
``confirmed[bucket][T] / total[bucket][T] >= SUCCESS_THRESHOLD`` (85 %).

A simple percentile-based fallback (the original implementation) is used
when the bucket data is still sparse (< ``MIN_BUCKET_OBSERVATIONS``
total observations).

Reference
---------
Bitcoin Core ``policy/fees.cpp`` — ``CBlockPolicyEstimator::processBlock``
and ``CBlockPolicyEstimator::estimateSmartFee``.
"""

import bisect
import json
import logging
import math
import os
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_BLOCK_HISTORY = 144  # blocks kept for the simple (fallback) estimator

#: Fee-rate bucket boundaries in sat/vB (logarithmic scale, ~40 values).
#: The first element is the lower bound of the first bucket; the last is the
#: upper bound of the last bucket.  ``_bucket_index`` maps any fee rate to
#: the appropriate bucket.
FEE_RATE_BUCKETS: List[float] = [
    1, 2, 3, 5, 7,
    10, 15, 20, 30, 50,
    75, 100, 150, 200, 300,
    500, 750, 1000, 1500, 2000,
    3000, 5000, 7500, 10000,
]

NUM_BUCKETS = len(FEE_RATE_BUCKETS)

#: Maximum confirmation target tracked in the bucket arrays.
MAX_CONF_TARGET = 25

#: Per-block exponential decay factor applied to all counters.
DECAY_FACTOR = 0.998

#: Minimum total observations across all buckets before the bucket estimator
#: is preferred over the simple fallback.
MIN_BUCKET_OBSERVATIONS = 100

#: Required success probability (confirmed / total) for a bucket to be
#: considered "good enough" for a given target.
SUCCESS_THRESHOLD = 0.85


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bucket_index(fee_rate: float) -> int:
    if fee_rate <= FEE_RATE_BUCKETS[0]:
        return 0
    idx = bisect.bisect_right(FEE_RATE_BUCKETS, fee_rate) - 1
    return min(idx, NUM_BUCKETS - 1)


# ---------------------------------------------------------------------------
# Legacy data structure (kept for fallback)
# ---------------------------------------------------------------------------

@dataclass
class BlockFeeData:
    """Fee rate statistics for a single confirmed block."""
    height: int
    fee_rates: List[float]
    median_fee_rate: float
    min_fee_rate: float


# ---------------------------------------------------------------------------
# Main estimator
# ---------------------------------------------------------------------------

class FeeEstimator:
    """Exponential-decay fee-rate-bucket estimator with percentile fallback.

    Public API
    ----------
    * ``process_block(block, height, mempool)`` — feed confirmed block data.
    * ``estimate_fee(conf_target)`` — fee rate in sat/vB (or ``None``).
    * ``estimate_fee_per_kb(conf_target)`` — fee rate in BTC/kB (or ``None``).
    * ``get_fee_summary()`` — diagnostic dict.
    """

    def __init__(self, max_history: int = MAX_BLOCK_HISTORY):
        # Bucket-based estimator state
        # confirmed[bucket][target] – how many txs in this bucket confirmed
        #   within exactly *target* blocks (after decay).
        # total[bucket][target] – how many txs in this bucket were tracked
        #   for this target window (confirmed OR still unconfirmed, after
        #   decay).
        self.confirmed: List[List[float]] = [
            [0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS)
        ]
        self.total: List[List[float]] = [
            [0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS)
        ]
        # Running count of total observations fed into the bucket arrays
        # (before decay), used to decide whether we have enough data.
        self._total_observations: int = 0

        # --- Simple fallback estimator state ---
        self.max_history = max_history
        self.block_history: deque[BlockFeeData] = deque(maxlen=max_history)

    # ------------------------------------------------------------------
    # Block processing
    # ------------------------------------------------------------------

    def process_block(self, block, height: int, mempool=None) -> None:
        """Record fee-rate data from a newly confirmed block.

        For every non-coinbase tx that was in our mempool we compute how
        many blocks it waited and update the bucket counters + decay.
        Also feeds the simple percentile fallback estimator.
        """
        # 1) Apply per-block exponential decay to ALL existing counters
        #    *before* recording the new observations (decay must precede new data).
        self._apply_decay()

        fee_rates: List[float] = []

        for tx in block.transactions:
            if tx.is_coinbase:
                continue

            if mempool is None:
                continue

            entry = mempool.get_transaction_entry(tx.get_txid())
            if entry is None or entry.fee <= 0:
                continue

            vsize = entry.size if entry.size > 0 else 1
            fee_rate = entry.fee / vsize
            fee_rates.append(fee_rate)

            # Determine how many blocks the tx waited.
            entry_height = getattr(entry, "height_added", 0)
            if entry_height > 0 and height >= entry_height:
                blocks_to_confirm = height - entry_height + 1  # 1-based
            else:
                blocks_to_confirm = 1  # conservative default

            self._record_confirmation(fee_rate, blocks_to_confirm)

        # Feed the simple fallback estimator
        if fee_rates:
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

    # ------------------------------------------------------------------
    # Estimation
    # ------------------------------------------------------------------

    def estimate_fee(self, conf_target: int = 6) -> Optional[float]:
        """Estimate fee rate in sat/vB for *conf_target*-block confirmation; returns None if data is sparse."""
        conf_target = max(1, min(conf_target, MAX_CONF_TARGET))

        # Try bucket-based estimation first.
        if self._total_observations >= MIN_BUCKET_OBSERVATIONS:
            bucket_estimate = self._estimate_from_buckets(conf_target)
            if bucket_estimate is not None:
                return bucket_estimate

        # Fallback to simple percentile method.
        return self._estimate_simple(conf_target)

    def estimate_fee_per_kb(self, conf_target: int = 6) -> Optional[float]:
        """Return fee estimate in BTC/kB."""
        rate = self.estimate_fee(conf_target)
        if rate is None:
            return None
        # sat/vB → BTC/kB:  rate * 1000 / 1e8
        return rate * 1000 / 1e8

    def get_fee_summary(self) -> Dict:
        """Return summary statistics for diagnostics."""
        summary: Dict = {
            "blocks_tracked": len(self.block_history),
            "bucket_observations": self._total_observations,
        }

        if self.block_history:
            medians = [b.median_fee_rate for b in self.block_history]
            # TODO: this could be cached
            summary.update({
                "oldest_height": self.block_history[0].height,
                "newest_height": self.block_history[-1].height,
                "median_fee_rate": sorted(medians)[len(medians) // 2],
                "min_fee_rate": min(
                    b.min_fee_rate for b in self.block_history
                ),
            })

        # Per-bucket snapshot (confirmed / total for a few representative
        # targets) — useful for debugging.
        bucket_snapshot: List[Dict] = []
        for i, boundary in enumerate(FEE_RATE_BUCKETS):
            row = dict(bucket_sat_vb=boundary)
            for t in (1, 3, 6, 12, 25):
                total = self.total[i][t]
                conf = self.confirmed[i][t]
                if total > 0:
                    row[f"target_{t}"] = round(conf / total, 3)
                else:
                    row[f"target_{t}"] = None
            bucket_snapshot.append(row)
        summary["buckets"] = bucket_snapshot

        return summary

    # ------------------------------------------------------------------
    # Internal: bucket estimator
    # ------------------------------------------------------------------

    def _apply_decay(self) -> None:
        for i in range(NUM_BUCKETS):
            for t in range(MAX_CONF_TARGET + 1):
                self.confirmed[i][t] *= DECAY_FACTOR
                self.total[i][t] *= DECAY_FACTOR

    def _record_confirmation(self, fee_rate: float, blocks_to_confirm: int) -> None:
        bucket = _bucket_index(fee_rate)
        self._total_observations += 1

        # Clamp to the range we track.
        btc = min(blocks_to_confirm, MAX_CONF_TARGET)

        # Targets where the tx was still unconfirmed (failed to confirm
        # within that window).
        for t in range(1, btc):
            self.total[bucket][t] += 1.0

        # Targets where the tx *did* confirm within the window (success).
        for t in range(btc, MAX_CONF_TARGET + 1):
            self.confirmed[bucket][t] += 1.0
            self.total[bucket][t] += 1.0

    def _estimate_from_buckets(self, conf_target: int) -> Optional[float]:
        for i in range(NUM_BUCKETS):
            total = self.total[i][conf_target]
            if total < 2.0:
                continue
            prob = self.confirmed[i][conf_target] / total
            if prob >= SUCCESS_THRESHOLD:
                return max(float(FEE_RATE_BUCKETS[i]), 1.0)

        # If no bucket passes, recommend the highest bucket as a
        # conservative estimate – but only if we have *some* data there.
        for i in range(NUM_BUCKETS - 1, -1, -1):
            total = self.total[i][conf_target]
            if total >= 2.0:
                return max(float(FEE_RATE_BUCKETS[i]), 1.0)

        return None

    # ------------------------------------------------------------------
    # Internal: simple percentile fallback
    # ------------------------------------------------------------------

    def _estimate_simple(self, conf_target: int) -> Optional[float]:
        """Original percentile-based estimator (fallback)."""
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

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_to_file(self, path: str) -> None:
        """Persist the bucket estimator state to a JSON file."""
        state = {
            "version": 1,
            "total_observations": self._total_observations,
            "confirmed": self.confirmed,
            "total": self.total,
            "block_history": [
                {
                    "height": b.height,
                    "fee_rates": b.fee_rates,
                    "median_fee_rate": b.median_fee_rate,
                    "min_fee_rate": b.min_fee_rate,
                }
                for b in self.block_history
            ],
        }
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(state, f)
            os.replace(tmp, path)
            logger.debug("Fee estimator: saved state to %s", path)
        except OSError as e:
            logger.warning("Fee estimator: failed to save state: %s", e)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def load_from_file(self, path: str) -> bool:
        """Load bucket estimator state from a JSON file.

        Returns True if state was loaded successfully.
        """
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Fee estimator: failed to load state: %s", e)
            return False

        if state.get("version") != 1:
            return False

        try:
            self._total_observations = state["total_observations"]

            # Restore bucket arrays (validate dimensions)
            confirmed = state["confirmed"]
            total = state["total"]
            if (len(confirmed) == NUM_BUCKETS
                    and len(total) == NUM_BUCKETS
                    and all(len(row) == MAX_CONF_TARGET + 1 for row in confirmed)
                    and all(len(row) == MAX_CONF_TARGET + 1 for row in total)):
                self.confirmed = confirmed
                self.total = total
            else:
                logger.warning("Fee estimator: dimension mismatch, ignoring")
                return False

            # Restore block history
            self.block_history.clear()
            for entry in state.get("block_history", []):
                self.block_history.append(BlockFeeData(
                    height=entry["height"],
                    fee_rates=entry["fee_rates"],
                    median_fee_rate=entry["median_fee_rate"],
                    min_fee_rate=entry["min_fee_rate"],
                ))

            logger.info(
                "Fee estimator: loaded state (%d observations, %d blocks)",
                self._total_observations, len(self.block_history),
            )
            return True
        except (KeyError, TypeError) as e:
            logger.warning("Fee estimator: corrupt state file: %s", e)
            return False
