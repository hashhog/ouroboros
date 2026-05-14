"""
Fee estimation using exponential-decay fee rate buckets.

Modelled on Bitcoin Core's ``CBlockPolicyEstimator`` (``policy/fees.cpp``).

Three horizons mirror Core's shortStats / feeStats / longStats:

  SHORT  — decay 0.962,   scale 1,  12 periods  (tracks up to 12 blocks)
  MEDIUM — decay 0.9952,  scale 2,  24 periods  (tracks up to 48 blocks)
  LONG   — decay 0.99931, scale 24, 42 periods  (tracks up to 1008 blocks)

For every confirmed transaction whose fee we know (because it was in our
mempool), the bucket corresponding to its fee rate is updated in all three
horizons.  Each horizon uses its own scale when mapping ``blocks_to_confirm``
to a period index.

All counters are subjected to per-horizon exponential decay on each block,
so recent data naturally outweighs stale observations.

To produce an estimate for a given confirmation target *T* the estimator
selects the appropriate horizon(s) and finds the lowest bucket where
``confirmed[bucket][period] / total[bucket][period] >= SUCCESS_THRESHOLD``
(85 %).

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
import os
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_BLOCK_HISTORY = 144  # blocks kept for the simple (fallback) estimator

#: Fee-rate bucket boundaries in sat/vB (logarithmic scale, ~40 values).
#: The first element is the lower bound of the first bucket; the last is the
#: upper bound of the last bucket.  ``_bucket_index`` maps any fee rate to
#: the appropriate bucket.
FEE_RATE_BUCKETS: list[float] = [
    1, 2, 3, 5, 7,
    10, 15, 20, 30, 50,
    75, 100, 150, 200, 300,
    500, 750, 1000, 1500, 2000,
    3000, 5000, 7500, 10000,
]

NUM_BUCKETS = len(FEE_RATE_BUCKETS)

#: Maximum confirmation target tracked across all horizons (LONG covers 1008).
MAX_CONF_TARGET = 1008


class Horizon(IntEnum):
    SHORT = 0
    MEDIUM = 1
    LONG = 2


#: Per-horizon exponential decay factor applied to all counters each block.
#: Mirrors Core's shortStats.decay / feeStats.decay / longStats.decay.
DECAY: dict[Horizon, float] = {
    Horizon.SHORT:  0.962,
    Horizon.MEDIUM: 0.9952,
    Horizon.LONG:   0.99931,
}

#: Block scale per horizon — one period = scale blocks.
SCALE: dict[Horizon, int] = {
    Horizon.SHORT:  1,
    Horizon.MEDIUM: 2,
    Horizon.LONG:   24,
}

#: Number of periods tracked per horizon.
PERIODS: dict[Horizon, int] = {
    Horizon.SHORT:  12,
    Horizon.MEDIUM: 24,
    Horizon.LONG:   42,
}

#: Backward-compat alias: the old single DECAY_FACTOR was 0.998 (between MED
#: and LONG).  Code that still imports DECAY_FACTOR gets the LONG value; the
#: constant is no longer used internally.
DECAY_FACTOR: float = DECAY[Horizon.LONG]

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
    fee_rates: list[float]
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
        # Per-horizon bucket arrays.
        # Each horizon h has arrays of shape [NUM_BUCKETS][PERIODS[h] + 1].
        # confirmed_h[bucket][period] – how many txs confirmed within *period*
        #   periods (after decay).
        # total_h[bucket][period] – how many txs were tracked for this period
        #   window (confirmed OR unconfirmed, after decay).
        def _make_horizon(h: Horizon) -> list[list[float]]:
            return [[0.0] * (PERIODS[h] + 1) for _ in range(NUM_BUCKETS)]

        self.short_stats: list[list[float]] = _make_horizon(Horizon.SHORT)
        self.short_totals: list[list[float]] = _make_horizon(Horizon.SHORT)

        self.med_stats: list[list[float]] = _make_horizon(Horizon.MEDIUM)
        self.med_totals: list[list[float]] = _make_horizon(Horizon.MEDIUM)

        self.long_stats: list[list[float]] = _make_horizon(Horizon.LONG)
        self.long_totals: list[list[float]] = _make_horizon(Horizon.LONG)

        # Convenience mapping for internal loops.
        self._conf: dict[Horizon, list[list[float]]] = {
            Horizon.SHORT:  self.short_stats,
            Horizon.MEDIUM: self.med_stats,
            Horizon.LONG:   self.long_stats,
        }
        self._total: dict[Horizon, list[list[float]]] = {
            Horizon.SHORT:  self.short_totals,
            Horizon.MEDIUM: self.med_totals,
            Horizon.LONG:   self.long_totals,
        }

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

        fee_rates: list[float] = []

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

    def estimate_fee(self, conf_target: int = 6) -> float | None:
        """Estimate fee rate in sat/vB for *conf_target*-block confirmation.

        Selects the tightest horizon that covers conf_target:
          SHORT  if conf_target <= 12  (scale=1,  12 periods)
          MEDIUM if conf_target <= 48  (scale=2,  24 periods → 48 blocks)
          LONG   if conf_target <= 1008 (scale=24, 42 periods → 1008 blocks)

        Returns None if data is sparse.
        """
        conf_target = max(1, min(conf_target, MAX_CONF_TARGET))

        # Select horizon based on target.
        short_max = PERIODS[Horizon.SHORT] * SCALE[Horizon.SHORT]    # 12
        med_max   = PERIODS[Horizon.MEDIUM] * SCALE[Horizon.MEDIUM]  # 48
        if conf_target <= short_max:
            horizon = Horizon.SHORT
        elif conf_target <= med_max:
            horizon = Horizon.MEDIUM
        else:
            horizon = Horizon.LONG

        # Try bucket-based estimation first.
        if self._total_observations >= MIN_BUCKET_OBSERVATIONS:
            bucket_estimate = self._estimate_from_buckets(conf_target, horizon)
            if bucket_estimate is not None:
                return bucket_estimate

        # Fallback to simple percentile method.
        return self._estimate_simple(conf_target)

    def estimate_fee_per_kb(self, conf_target: int = 6) -> float | None:
        """Return fee estimate in BTC/kB."""
        rate = self.estimate_fee(conf_target)
        if rate is None:
            return None
        # sat/vB → BTC/kB:  rate * 1000 / 1e8
        return rate * 1000 / 1e8

    def get_fee_summary(self) -> dict:
        """Return summary statistics for diagnostics."""
        summary: dict = {
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

        # Per-bucket snapshot — use LONG horizon for representative targets.
        conf_arr = self._conf[Horizon.LONG]
        total_arr = self._total[Horizon.LONG]
        bucket_snapshot: list[dict] = []
        for i, boundary in enumerate(FEE_RATE_BUCKETS):
            row = {"bucket_sat_vb": boundary}
            for t in (1, 3, 6, 12, 25):
                # Convert block target → LONG period (clamp to tracked range).
                period = min(
                    max(1, t // SCALE[Horizon.LONG]),
                    PERIODS[Horizon.LONG],
                )
                total = total_arr[i][period]
                conf = conf_arr[i][period]
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
        for h in Horizon:
            d = DECAY[h]
            conf_h = self._conf[h]
            total_h = self._total[h]
            periods = PERIODS[h]
            for i in range(NUM_BUCKETS):
                for t in range(periods + 1):
                    conf_h[i][t] *= d
                    total_h[i][t] *= d

    def _record_confirmation(self, fee_rate: float, blocks_to_confirm: int) -> None:
        bucket = _bucket_index(fee_rate)
        self._total_observations += 1

        for h in Horizon:
            scale = SCALE[h]
            periods = PERIODS[h]
            conf_h = self._conf[h]
            total_h = self._total[h]

            # Convert block count to this horizon's period index.
            # A tx that confirmed in *blocks_to_confirm* blocks confirmed
            # within ceil(blocks_to_confirm / scale) periods.
            period = (blocks_to_confirm + scale - 1) // scale
            # Clamp to the range we track.
            period = min(period, periods)

            # Periods where the tx was still unconfirmed (failed to confirm
            # within that shorter window).
            for p in range(1, period):
                total_h[bucket][p] += 1.0

            # Periods where the tx *did* confirm within the window (success).
            for p in range(period, periods + 1):
                conf_h[bucket][p] += 1.0
                total_h[bucket][p] += 1.0

    def _estimate_from_buckets(self, conf_target: int, horizon: Horizon) -> float | None:
        """Look up the lowest fee-rate bucket meeting SUCCESS_THRESHOLD for the
        given *conf_target* blocks in the specified *horizon*.

        *conf_target* is in blocks; it is converted to the horizon's period
        index before indexing the arrays.
        """
        scale = SCALE[horizon]
        periods = PERIODS[horizon]
        conf_h = self._conf[horizon]
        total_h = self._total[horizon]

        # Convert block target to period index for this horizon.
        period = min(max(1, (conf_target + scale - 1) // scale), periods)

        for i in range(NUM_BUCKETS):
            total = total_h[i][period]
            if total < 2.0:
                continue
            prob = conf_h[i][period] / total
            if prob >= SUCCESS_THRESHOLD:
                return max(float(FEE_RATE_BUCKETS[i]), 1.0)

        # If no bucket passes, recommend the highest bucket as a
        # conservative estimate – but only if we have *some* data there.
        for i in range(NUM_BUCKETS - 1, -1, -1):
            total = total_h[i][period]
            if total >= 2.0:
                return max(float(FEE_RATE_BUCKETS[i]), 1.0)

        return None

    # ------------------------------------------------------------------
    # Internal: simple percentile fallback
    # ------------------------------------------------------------------

    def _estimate_simple(self, conf_target: int) -> float | None:
        """Original percentile-based estimator (fallback)."""
        if len(self.block_history) < 3:
            return None

        sample_depth = min(len(self.block_history), max(conf_target * 2, 6))

        all_rates: list[float] = []
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
            "short_confirmed": self.short_stats,
            "short_total":     self.short_totals,
            "med_confirmed":   self.med_stats,
            "med_total":       self.med_totals,
            "long_confirmed":  self.long_stats,
            "long_total":      self.long_totals,
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
            with open(path) as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Fee estimator: failed to load state: %s", e)
            return False

        if state.get("version") != 1:
            return False

        try:
            self._total_observations = state["total_observations"]

            def _check_dims(arr: list, h: Horizon) -> bool:
                return (
                    len(arr) == NUM_BUCKETS
                    and all(len(row) == PERIODS[h] + 1 for row in arr)
                )

            for key, attr_conf, attr_tot, h in (
                ("short", "short_stats", "short_totals", Horizon.SHORT),
                ("med",   "med_stats",   "med_totals",   Horizon.MEDIUM),
                ("long",  "long_stats",  "long_totals",  Horizon.LONG),
            ):
                confirmed = state[f"{key}_confirmed"]
                total     = state[f"{key}_total"]
                if not (_check_dims(confirmed, h) and _check_dims(total, h)):
                    logger.warning("Fee estimator: dimension mismatch (%s), ignoring", key)
                    return False
                setattr(self, attr_conf, confirmed)
                setattr(self, attr_tot,  total)

            # Keep the convenience dicts in sync.
            self._conf = {
                Horizon.SHORT:  self.short_stats,
                Horizon.MEDIUM: self.med_stats,
                Horizon.LONG:   self.long_stats,
            }
            self._total = {
                Horizon.SHORT:  self.short_totals,
                Horizon.MEDIUM: self.med_totals,
                Horizon.LONG:   self.long_totals,
            }

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
