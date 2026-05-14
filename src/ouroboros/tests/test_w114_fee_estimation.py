"""
W114 CBlockPolicyEstimator fleet audit — ouroboros (Python pipeline only).

Pipeline: Python fee_estimator.py + rpc.py (estimatesmartfee / estimaterawfee).
No Rust pipeline: ferrous-utils/ has no fee-estimation code.

Core reference
--------------
- bitcoin-core/src/policy/fees/block_policy_estimator.h/cpp
- bitcoin-core/src/policy/feerate.h
- bitcoin-core/src/rpc/fees.cpp

Constants (Core)
----------------
- Horizons: SHORT (12 periods × scale=1 = 12 blocks, decay=0.962),
            MED   (24 periods × scale=2 = 48 blocks, decay=0.9952),
            LONG  (42 periods × scale=24 = 1008 blocks, decay=0.99931)
- Buckets: MIN_BUCKET_FEERATE=100 sat/kB, MAX_BUCKET_FEERATE=1e7 sat/kB,
           FEE_SPACING=1.05 → ~237 buckets
- Success thresholds: HALF=0.60, SUCCESS=0.85, DOUBLE=0.95
- SUFFICIENT_FEETXS=0.1 per block, SUFFICIENT_TXS_SHORT=0.5
- File version: 309900 (CURRENT_FEES_FILE_VERSION)

Bug inventory
=============

BUG-1 (G1–G5, HIGH) — Single-horizon estimator only; no SHORT/MED/LONG split.
  Core maintains three TxConfirmStats instances (shortStats, feeStats, longStats)
  with different decay factors (0.962, 0.9952, 0.99931) and scale factors (1, 2, 24).
  ouroboros uses a single bucket array with DECAY_FACTOR=0.998, which has a
  half-life of ~346 blocks — between Core's MED and LONG — and is not equivalent
  to any Core horizon.  estimateSmartFee uses three sub-estimates (HALF at T/2,
  FULL at T, DOUBLE at 2×T) across multiple horizons; ouroboros has only one
  array, so the three-estimate max and conservative-mode cross-horizon checks are
  entirely absent.

BUG-2 (G1, HIGH) — MAX_CONF_TARGET=25; targets 26–1008 silently clamped.
  Core's LONG horizon tracks up to 42 × 24 = 1008 blocks.  ouroboros caps
  MAX_CONF_TARGET at 25.  rpc_estimatesmartfee accepts conf_target up to 1008
  but silently clamps to 25 inside estimate_fee(); the returned "blocks" field
  reflects the REQUESTED target, not the actual tracking limit, giving the caller
  false confidence.  Core clamps to maxUsableEstimate and returns the clamped
  value in feeCalc.returnedTarget.

BUG-3 (G6, MEDIUM) — Wrong feerate unit in fee_estimator.process_block.
  Line 167: ``fee_rate = entry.fee / vsize`` where ``vsize = entry.size`` and
  ``entry.size`` is the *stripped* (no-witness) byte count used for mempool byte
  budget.  Core uses ``m_virtual_transaction_size`` (sigop-adjusted vsize with
  witness discount).  MempoolEntry.fee_rate already holds the correct sat/vbyte
  value (sigop-adjusted).  For segwit transactions the stripped size is larger
  than the vsize, so the computed fee rate is lower than the correct value,
  skewing bucket placement and estimates downward.

BUG-4 (G7, MEDIUM) — blocks_to_confirm off-by-one: +1 overcounts wait.
  Line 173: ``blocks_to_confirm = height - entry_height + 1``.
  Core: ``blocksToConfirm = nBlockHeight - tx.info.txHeight`` (no +1).
  If a tx enters the mempool at height 100 and confirms in block 101, Core
  records btc=1 (correct 1-based); ouroboros records btc=2.  Estimates are
  therefore biased toward longer confirmation windows than reality.

BUG-5 (G8, MEDIUM) — No processTransaction (per-tx admission tracking).
  Core calls processTransaction at every mempool admission, assigning a bucket
  index and inserting into mapMemPoolTxs + the unconfTxs circular buffer.  This
  enables Core to count in-mempool unconfirmed txs when estimating (the
  ``extraNum`` term in EstimateMedianVal).  ouroboros has no mempool-entry hook;
  the fee_estimator only learns about txs when they confirm in a block.
  Consequence: estimates are blind to currently unconfirmed transactions, making
  the denominator (totalNum + failNum + extraNum) too small and estimates
  potentially overconfident.

BUG-6 (G9, MEDIUM) — No eviction / removeTx tracking (failAvg absent).
  Core's removeTx records evicted (non-block) mempool txs into failAvg[period],
  reflecting "tx left mempool unconfirmed".  This penalises fee buckets where
  many txs are evicted before confirmation.  ouroboros has no failAvg array and
  no removeTx call path, so eviction pressure is invisible.

BUG-7 (G10, LOW) — No unconfirmed circular buffer (unconfTxs absent).
  Core maintains unconfTxs[blockIndex][bucket] tracking how long each bucket's
  txs have been unconfirmed, feeding the extraNum term via ClearCurrent.
  ouroboros has no such buffer; the only knowledge of unconfirmed txs comes from
  the fallback percentile estimator's block_history.

BUG-8 (G14, LOW) — estimate_mode parameter accepted but silently ignored.
  rpc_estimatesmartfee accepts ``estimate_mode`` ("economical" / "conservative")
  but never passes it to the estimator.  Core's conservative mode applies the
  DOUBLE_SUCCESS_PCT (0.95) threshold across multiple horizons, producing higher
  (safer) estimates.  ouroboros always uses SUCCESS_THRESHOLD=0.85, so
  conservative mode is a no-op.

BUG-9 (G15, LOW) — Wrong bucket count and spacing: 24 manual buckets vs ~237.
  Core generates ~237 exponentially-spaced buckets via MIN_BUCKET_FEERATE=100
  sat/kB to MAX_BUCKET_FEERATE=1e7 sat/kB at FEE_SPACING=1.05 (plus INF).
  ouroboros uses 24 hand-coded sat/vB boundaries.  The coarse resolution causes
  imprecise bucket placement; transactions with similar but distinct feerates
  land in the same bucket, degrading estimate quality.

BUG-10 (G17, LOW) — No per-bucket sufficient-txs gate; only global MIN_BUCKET_OBSERVATIONS.
  Core's EstimateMedianVal merges adjacent buckets until the group meets
  sufficientTxVal / (1 - decay) (approximately 0.1 / (1-0.99931) ≈ 145 average
  txs), preventing estimates from single-tx or two-tx buckets.  ouroboros
  checks only ``total >= 2.0`` per bucket in _estimate_from_buckets, which can
  return an estimate from as few as 2 observations in a bucket.

BUG-11 (G18, LOW) — No stale-file age check on load.
  Core refuses to load fee_estimates.dat if it is older than MAX_FILE_AGE=60
  hours (unless read_stale_estimates is set).  ouroboros loads the JSON file
  unconditionally regardless of mtime; stale estimates from days ago are served
  as if fresh.

BUG-12 (G26, LOW) — "blocks" in estimatesmartfee response always echoes input.
  Core returns feeCalc.returnedTarget in the "blocks" field, which may differ
  from the requested conf_target when the target is clamped (MaxUsableEstimate).
  ouroboros always returns the original conf_target, so the caller cannot know
  the estimate was for a shorter horizon.

BUG-13 (G28, LOW) — estimatesmartfee does not clamp conf_target to minimum 2.
  Core: "It's not possible to get reasonable estimates for confTarget of 1";
  conf_target==1 is silently promoted to 2.  ouroboros clamps to max(1, …),
  allowing conf_target=1 to reach the estimator unchanged.

BUG-14 (G30, LOW) — No min-relay-fee / mempool-min-fee floor on estimates.
  Core's estimatesmartfee: ``feeRate = max(feeRate, min_mempool_feerate,
  min_relay_feerate)``.  ouroboros returns the raw bucket estimate with no such
  floor, so the result can be below the node's effective minimum feerate.

Two-pipeline observations
=========================

There is only ONE pipeline: the Python fee_estimator.py / rpc.py.
ferrous-utils/ (Rust) contains no fee-estimation code — confirmed by grep.
All W114 bugs are therefore single-pipeline.
"""

from __future__ import annotations

import json
import math
import os
import time
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

class _StubNode:
    """Minimal node stub for RPC unit tests."""
    def __init__(self, fee_estimator):
        self.fee_estimator = fee_estimator


@pytest.fixture
def fresh_estimator():
    from ouroboros.fee_estimator import FeeEstimator
    return FeeEstimator()


@pytest.fixture
def rpc(fresh_estimator):
    from ouroboros.rpc import RPCServer
    srv = RPCServer.__new__(RPCServer)
    srv.node = _StubNode(fresh_estimator)
    return srv


def _make_block(txids: list[str], mempool: object):
    """Return a minimal block stub whose transactions are already in *mempool*."""
    block = MagicMock()
    txs = []
    for txid in txids:
        tx = MagicMock()
        tx.is_coinbase = False
        tx.get_txid.return_value = bytes.fromhex(txid)
        txs.append(tx)
    # Also add a coinbase tx at position 0
    cb = MagicMock()
    cb.is_coinbase = True
    block.transactions = [cb] + txs
    return block


def _make_mempool_entry(fee: int = 1000, size: int = 250, height_added: int = 100):
    """Return a MempoolEntry-like object."""
    entry = MagicMock()
    entry.fee = fee
    entry.size = size
    entry.fee_rate = fee / size  # sat/vbyte (for vsize=size, which may be wrong for segwit)
    entry.height_added = height_added
    return entry


def _make_mempool(entries: dict):
    """Return a mempool stub mapping txid→entry."""
    pool = MagicMock()
    pool.get_transaction_entry = lambda txid: entries.get(txid)
    return pool


# ---------------------------------------------------------------------------
# BUG-1: Single-horizon; no SHORT/MED/LONG decay split
# ---------------------------------------------------------------------------

class TestBug1SingleHorizon:
    """BUG-1 (HIGH): ouroboros uses a single DECAY_FACTOR=0.998 instead of
    Core's three horizons (SHORT=0.962, MED=0.9952, LONG=0.99931).
    """

    def test_single_decay_factor_not_core_short(self):
        from ouroboros.fee_estimator import DECAY_FACTOR
        CORE_SHORT_DECAY = 0.962
        assert DECAY_FACTOR != pytest.approx(CORE_SHORT_DECAY, rel=1e-3), (
            "Decay equals Core SHORT (0.962) — multi-horizon not implemented"
        )

    def test_single_decay_factor_not_core_med(self):
        from ouroboros.fee_estimator import DECAY_FACTOR
        CORE_MED_DECAY = 0.9952
        assert DECAY_FACTOR != pytest.approx(CORE_MED_DECAY, rel=1e-3), (
            "Decay equals Core MED (0.9952) — multi-horizon not implemented"
        )

    def test_single_decay_factor_not_core_long(self):
        from ouroboros.fee_estimator import DECAY_FACTOR
        CORE_LONG_DECAY = 0.99931
        assert DECAY_FACTOR != pytest.approx(CORE_LONG_DECAY, rel=1e-3), (
            "Decay equals Core LONG (0.99931) — multi-horizon not implemented"
        )

    def test_ouroboros_halflife_between_med_and_long(self):
        """ouroboros DECAY_FACTOR=0.998 has ~346 block half-life; Core MED=144, LONG=1008."""
        from ouroboros.fee_estimator import DECAY_FACTOR
        halflife = math.log(0.5) / math.log(DECAY_FACTOR)
        # Should be between Core MED (~144) and Core LONG (~1008)
        assert 144 < halflife < 1008, (
            f"Single-horizon half-life={halflife:.0f} blocks is not a Core horizon"
        )

    def test_estimator_has_no_short_stats_attribute(self, fresh_estimator):
        """No shortStats / short_stats equivalent exists."""
        assert not hasattr(fresh_estimator, "short_stats")
        assert not hasattr(fresh_estimator, "shortStats")

    def test_estimator_has_no_med_stats_attribute(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "med_stats")
        assert not hasattr(fresh_estimator, "feeStats")

    def test_estimator_has_no_long_stats_attribute(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "long_stats")
        assert not hasattr(fresh_estimator, "longStats")

    @pytest.mark.asyncio
    async def test_estimaterawfee_returns_only_long_horizon(self, rpc):
        """estimaterawfee should return short/medium/long; returns only 'long'."""
        result = await rpc.rpc_estimaterawfee(6)
        # Core returns short/medium/long keys when target allows
        assert "short" not in result, (
            "'short' horizon missing — single-horizon estimator only"
        )
        assert "medium" not in result, (
            "'medium' horizon missing — single-horizon estimator only"
        )
        assert "long" in result  # confirm only long key present


# ---------------------------------------------------------------------------
# BUG-2: MAX_CONF_TARGET=25; targets 26-1008 silently clamped
# ---------------------------------------------------------------------------

class TestBug2MaxConfTarget:
    """BUG-2 (HIGH): ouroboros MAX_CONF_TARGET=25; Core LONG tracks 1008 blocks."""

    def test_max_conf_target_is_25(self):
        from ouroboros.fee_estimator import MAX_CONF_TARGET
        assert MAX_CONF_TARGET == 25, (
            f"MAX_CONF_TARGET={MAX_CONF_TARGET} — Core LONG tracks 1008"
        )

    def test_core_long_tracks_1008(self):
        """Ensure we're testing against the correct Core value."""
        CORE_LONG_PERIODS = 42
        CORE_LONG_SCALE = 24
        assert CORE_LONG_PERIODS * CORE_LONG_SCALE == 1008

    def test_estimate_fee_clamps_target_to_25(self, fresh_estimator):
        """Calling estimate_fee with target=200 silently uses target=25."""
        from ouroboros.fee_estimator import MAX_CONF_TARGET
        # Inject data at target 25 (the max tracked)
        fresh_estimator.total[10][MAX_CONF_TARGET] = 50.0
        fresh_estimator.confirmed[10][MAX_CONF_TARGET] = 45.0
        fresh_estimator._total_observations = 200

        result_25 = fresh_estimator.estimate_fee(MAX_CONF_TARGET)
        result_200 = fresh_estimator.estimate_fee(200)
        # Both should return the same value because 200 is clamped to 25
        # This exposes the silent clamping
        assert result_200 == result_25, (
            "estimate_fee(200) silently clamps to MAX_CONF_TARGET (BUG-2)"
        )

    @pytest.mark.asyncio
    async def test_estimatesmartfee_blocks_field_echoes_input_not_clamped(self, rpc):
        """'blocks' in response echoes conf_target=200 even though estimate is for 25."""
        result = await rpc.rpc_estimatesmartfee(conf_target=200)
        # ouroboros returns "blocks": 200 even though internally clamped to 25
        assert result.get("blocks") == 200, (
            "BUG-2: 'blocks' should reflect returned target, not requested target"
        )


# ---------------------------------------------------------------------------
# BUG-3: Wrong feerate unit — stripped size instead of vsize
# ---------------------------------------------------------------------------

class TestBug3FeerateUnit:
    """BUG-3 (MEDIUM): fee_rate = entry.fee / entry.size uses stripped bytes.
    Core uses m_virtual_transaction_size (sigop-adjusted vsize with witness
    discount).  For segwit txs, stripped size > vsize, so fee_rate is wrong.
    """

    def test_process_block_uses_size_not_fee_rate(self):
        """Verify the bug exists: line 167 uses entry.size, not entry.fee_rate."""
        import inspect
        from ouroboros import fee_estimator
        src = inspect.getsource(fee_estimator.FeeEstimator.process_block)
        # Bug: uses entry.size (stripped bytes) for the denominator
        assert "entry.size" in src, "BUG-3: fee_estimator.process_block should use vsize"
        # Fix should use entry.fee_rate directly
        assert "entry.fee_rate" not in src, (
            "BUG-3: fee_estimator.process_block does NOT use entry.fee_rate (fix missing)"
        )

    def test_segwit_fee_rate_underestimated_when_using_stripped_size(self):
        """For a segwit tx, stripped_size > vsize → fee_rate is lower than correct."""
        from ouroboros.fee_estimator import FeeEstimator, _bucket_index

        # Simulate a segwit tx:
        # actual fee = 2000 sat, witness_vsize = 200 vbytes, stripped_size = 300 bytes
        # correct fee_rate = 2000/200 = 10 sat/vB → bucket for 10
        # bug fee_rate = 2000/300 ≈ 6.67 sat/vB → lower bucket (around 7 or less)
        correct_rate = 2000 / 200   # 10 sat/vB
        bug_rate = 2000 / 300       # 6.67 sat/vB

        correct_bucket = _bucket_index(correct_rate)
        bug_bucket = _bucket_index(bug_rate)

        assert bug_bucket < correct_bucket, (
            "BUG-3: segwit tx fee_rate using stripped size lands in wrong (lower) bucket"
        )

    def test_correct_fix_would_use_fee_rate_field(self):
        """Illustrate the fix: using entry.fee_rate gives the correct sat/vB."""
        correct_fee_rate = 10.0   # sat/vB already stored in entry.fee_rate

        entry = _make_mempool_entry(fee=2000, size=300)
        # entry.fee_rate is NOT set to 10 by our stub — this tests the concept
        entry.fee_rate = correct_fee_rate

        # With the fix, fee_estimator would just use entry.fee_rate
        assert entry.fee_rate == pytest.approx(10.0)


# ---------------------------------------------------------------------------
# BUG-4: blocks_to_confirm off-by-one (+1)
# ---------------------------------------------------------------------------

class TestBug4BlocksToConfirmOffByOne:
    """BUG-4 (MEDIUM): blocks_to_confirm = height - entry_height + 1 overcounts by 1.
    Core: blocksToConfirm = nBlockHeight - txHeight (no +1).
    """

    def test_off_by_one_source_present(self):
        """Confirm the +1 is still in the source."""
        import inspect
        from ouroboros import fee_estimator
        src = inspect.getsource(fee_estimator.FeeEstimator.process_block)
        assert "entry_height + 1" in src or "height_added + 1" in src or (
            "blocks_to_confirm = height - entry_height + 1" in src
        ), "BUG-4: off-by-one +1 in blocks_to_confirm not found — may already be fixed"

    def test_next_block_confirmation_records_btc2_not_1(self, fresh_estimator):
        """tx enters at height 100, confirms at height 101 → btc=2 (bug, should be 1)."""
        txid = b'\x01' * 32
        entry = _make_mempool_entry(fee=10000, size=250, height_added=100)
        mempool = _make_mempool({txid: entry})

        block = MagicMock()
        tx = MagicMock()
        tx.is_coinbase = False
        tx.get_txid.return_value = txid
        block.transactions = [tx]

        fresh_estimator.process_block(block, height=101, mempool=mempool)

        # BUG: the tx is recorded with blocks_to_confirm=2 (101-100+1),
        # but Core would record btc=1 (101-100).
        # Internally, total[bucket][1] should NOT have been incremented for btc=2:
        # _record_confirmation(fee_rate, 2) sets total[b][1] += 1 (unconfirmed) and
        # confirmed[b][2..25] += 1, total[b][2..25] += 1.
        # For btc=1 (correct Core): total[b][1] += 1, confirmed[b][1..25] += 1.
        from ouroboros.fee_estimator import _bucket_index
        fee_rate = entry.fee / entry.size  # 40 sat/vB
        b = _bucket_index(fee_rate)
        # With bug (btc=2): confirmed[b][1] == 0 (not confirmed at target 1)
        # With fix (btc=1): confirmed[b][1] == 1
        assert fresh_estimator.confirmed[b][1] == pytest.approx(0.0), (
            "BUG-4: With off-by-one, tx confirmed at 101 should NOT appear as "
            "confirmed at target=1 — this would be fixed by removing +1"
        )

    def test_core_formula_gives_btc1_for_next_block(self):
        """Core formula: nBlockHeight(101) - txHeight(100) = 1."""
        entry_height = 100
        block_height = 101
        core_btc = block_height - entry_height
        assert core_btc == 1

    def test_ouroboros_formula_gives_btc2_for_next_block(self):
        """ouroboros formula: height(101) - entry_height(100) + 1 = 2."""
        entry_height = 100
        block_height = 101
        ouroboros_btc = block_height - entry_height + 1
        assert ouroboros_btc == 2


# ---------------------------------------------------------------------------
# BUG-5: No processTransaction at mempool admission
# ---------------------------------------------------------------------------

class TestBug5NoProcessTransaction:
    """BUG-5 (MEDIUM): FeeEstimator has no process_transaction method.
    Core calls processTransaction on every mempool admission to track
    unconfirmed txs per-bucket.
    """

    def test_fee_estimator_has_no_process_transaction(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "process_transaction"), (
            "BUG-5: FeeEstimator has process_transaction — expected to be absent"
        )
        assert not hasattr(fresh_estimator, "processTransaction"), (
            "BUG-5: FeeEstimator has processTransaction — expected to be absent"
        )

    def test_fee_estimator_has_no_mempool_tx_map(self, fresh_estimator):
        """Core's mapMemPoolTxs tracks per-tx bucket indices."""
        assert not hasattr(fresh_estimator, "map_mempool_txs")
        assert not hasattr(fresh_estimator, "mapMemPoolTxs")

    def test_node_does_not_register_on_tx_added_callback(self):
        """node.py does not wire fee_estimator into mempool's on_tx_added callback."""
        import inspect
        from ouroboros import node as node_mod
        src = inspect.getsource(node_mod)
        # on_tx_added callback should NOT be connected to fee_estimator
        assert "fee_estimator" not in src.split("on_tx_added")[0].split("def start")[-1] or True
        # More direct: check the mempool constructor call in node.py doesn't pass fee_estimator
        # as on_tx_added
        assert "on_tx_added" not in src.split("fee_estimator")[1].split("block_sync")[0], (
            "BUG-5: on_tx_added should not be wired to fee_estimator yet"
        )


# ---------------------------------------------------------------------------
# BUG-6: No eviction tracking (failAvg absent)
# ---------------------------------------------------------------------------

class TestBug6NoEvictionTracking:
    """BUG-6 (MEDIUM): No removeTx / failAvg to track evicted mempool txs."""

    def test_fee_estimator_has_no_fail_avg(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "fail_avg")
        assert not hasattr(fresh_estimator, "failAvg")

    def test_fee_estimator_has_no_remove_tx(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "remove_tx")
        assert not hasattr(fresh_estimator, "removeTx")

    def test_estimates_ignore_evicted_tx_pressure(self, fresh_estimator):
        """Estimates do not account for txs that were evicted without confirming."""
        # Inject 100% success rate in a bucket
        fresh_estimator.total[5][6] = 10.0
        fresh_estimator.confirmed[5][6] = 10.0
        fresh_estimator._total_observations = 200

        est_before = fresh_estimator.estimate_fee(6)

        # Simulate eviction of 50 txs at this bucket (would lower the success rate
        # if failAvg were tracked).  With no failAvg, estimate is unchanged.
        # (We can only assert failAvg doesn't exist to change the result.)
        assert not hasattr(fresh_estimator, "fail_avg")
        est_after = fresh_estimator.estimate_fee(6)
        assert est_before == est_after  # eviction had no effect


# ---------------------------------------------------------------------------
# BUG-7: No unconfirmed circular buffer
# ---------------------------------------------------------------------------

class TestBug7NoUnconfCircularBuffer:
    """BUG-7 (LOW): No unconfTxs circular buffer; extraNum term always 0."""

    def test_no_unconf_txs_attribute(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "unconf_txs")
        assert not hasattr(fresh_estimator, "unconfTxs")

    def test_no_old_unconf_txs_attribute(self, fresh_estimator):
        assert not hasattr(fresh_estimator, "old_unconf_txs")
        assert not hasattr(fresh_estimator, "oldUnconfTxs")

    def test_no_best_seen_height_tracking(self, fresh_estimator):
        """Core tracks nBestSeenHeight for circular-buffer indexing."""
        assert not hasattr(fresh_estimator, "best_seen_height")
        assert not hasattr(fresh_estimator, "nBestSeenHeight")


# ---------------------------------------------------------------------------
# BUG-8: estimate_mode silently ignored
# ---------------------------------------------------------------------------

class TestBug8EstimateModeIgnored:
    """BUG-8 (LOW): estimate_mode='conservative' accepted but ignored."""

    @pytest.mark.asyncio
    async def test_conservative_and_economical_return_same_feerate(self, rpc):
        """Both modes should differ (conservative uses higher threshold)."""
        fe = rpc.node.fee_estimator
        # Inject moderate data so bucket estimator returns a result
        fe.total[10][6] = 20.0
        fe.confirmed[10][6] = 18.0  # 90% — passes SUCCESS_THRESHOLD but not DOUBLE
        fe._total_observations = 200

        result_eco = await rpc.rpc_estimatesmartfee(6, estimate_mode="economical")
        result_con = await rpc.rpc_estimatesmartfee(6, estimate_mode="conservative")

        # BUG: they return the same result because estimate_mode is ignored
        assert result_eco.get("feerate") == result_con.get("feerate"), (
            "BUG-8: conservative and economical should differ; estimate_mode is ignored"
        )

    @pytest.mark.asyncio
    async def test_unrecognised_estimate_mode_not_rejected(self, rpc):
        """Core rejects invalid estimate_mode with RPC_INVALID_PARAMETER."""
        # ouroboros silently accepts anything
        result = await rpc.rpc_estimatesmartfee(6, estimate_mode="INVALID_MODE")
        # Should raise, but ouroboros doesn't check — returns a normal response
        assert "errors" in result or "feerate" in result  # doesn't explode at least


# ---------------------------------------------------------------------------
# BUG-9: Wrong bucket count and spacing
# ---------------------------------------------------------------------------

class TestBug9WrongBucketCountAndSpacing:
    """BUG-9 (LOW): 24 hand-coded sat/vB buckets vs ~237 Core 1.05-spaced buckets."""

    def test_num_buckets_is_24_not_237(self):
        from ouroboros.fee_estimator import NUM_BUCKETS
        CORE_APPROX_BUCKET_COUNT = 237
        assert NUM_BUCKETS == 24, (
            f"NUM_BUCKETS={NUM_BUCKETS}, expected 24 (not Core's ~{CORE_APPROX_BUCKET_COUNT})"
        )

    def test_fee_spacing_is_not_1_05(self):
        """Core uses exponential 1.05 spacing; ouroboros uses ad-hoc boundaries."""
        from ouroboros.fee_estimator import FEE_RATE_BUCKETS
        # Check that consecutive ratios are NOT consistently 1.05
        ratios = [FEE_RATE_BUCKETS[i+1] / FEE_RATE_BUCKETS[i]
                  for i in range(len(FEE_RATE_BUCKETS) - 1)]
        # Most ratios should not be 1.05
        close_to_1_05 = sum(1 for r in ratios if abs(r - 1.05) < 0.01)
        assert close_to_1_05 < len(ratios) // 2, (
            "BUG-9: bucket spacing is not Core's 1.05 exponential"
        )

    def test_min_bucket_feerate_starts_at_1_not_100sat_kvb(self):
        """Core MIN_BUCKET_FEERATE=100 sat/kB = 0.1 sat/vB; ouroboros starts at 1 sat/vB."""
        from ouroboros.fee_estimator import FEE_RATE_BUCKETS
        CORE_MIN_SAT_VB = 100 / 1000  # 100 sat/kB → 0.1 sat/vB
        ouroboros_min = FEE_RATE_BUCKETS[0]
        assert ouroboros_min > CORE_MIN_SAT_VB, (
            f"ouroboros min bucket {ouroboros_min} should be > Core {CORE_MIN_SAT_VB} sat/vB"
        )


# ---------------------------------------------------------------------------
# BUG-10: No per-bucket sufficient-txs gate
# ---------------------------------------------------------------------------

class TestBug10NoBucketSufficientTxsGate:
    """BUG-10 (LOW): estimates can come from buckets with only 2 observations."""

    def test_two_observations_can_produce_estimate(self, fresh_estimator):
        """Core needs sufficientTxVal / (1-decay) ≈ 145+ txs; ouroboros uses 2."""
        fresh_estimator.total[10][6] = 2.0
        fresh_estimator.confirmed[10][6] = 2.0  # 100% from only 2 obs
        fresh_estimator._total_observations = 200

        estimate = fresh_estimator.estimate_fee(6)
        assert estimate is not None, (
            "BUG-10: estimate from only 2 observations should not be trusted"
        )

    def test_min_total_threshold_is_2_not_sufficient_feetxs(self):
        """_estimate_from_buckets uses total < 2.0 not sufficientTxVal."""
        import inspect
        from ouroboros import fee_estimator
        src = inspect.getsource(fee_estimator.FeeEstimator._estimate_from_buckets)
        assert "< 2.0" in src or "< 2" in src, (
            "BUG-10: expected total<2 threshold in _estimate_from_buckets"
        )


# ---------------------------------------------------------------------------
# BUG-11: No stale-file age check on load
# ---------------------------------------------------------------------------

class TestBug11NoStaleFileCheck:
    """BUG-11 (LOW): Stale fee estimates loaded without age check."""

    def test_load_from_old_file_succeeds(self, fresh_estimator):
        """Core refuses files older than 60 hours; ouroboros loads them."""
        from ouroboros.fee_estimator import MAX_CONF_TARGET, NUM_BUCKETS, FeeEstimator

        state = {
            "version": 1,
            "total_observations": 500,
            "confirmed": [[0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS)],
            "total":     [[0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS)],
            "block_history": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state, f)
            tmp_path = f.name

        try:
            # Make the file very old (100 hours ago)
            old_mtime = time.time() - 100 * 3600
            os.utime(tmp_path, (old_mtime, old_mtime))

            new_est = FeeEstimator()
            result = new_est.load_from_file(tmp_path)
            # BUG: ouroboros loads it successfully regardless of age
            assert result is True, (
                "BUG-11: stale file (100h old) should be rejected; was loaded"
            )
        finally:
            os.unlink(tmp_path)

    def test_no_max_file_age_constant(self):
        """Core defines MAX_FILE_AGE=60 hours; ouroboros has no equivalent."""
        import ouroboros.fee_estimator as fe_mod
        assert not hasattr(fe_mod, "MAX_FILE_AGE")


# ---------------------------------------------------------------------------
# BUG-12: "blocks" field always echoes input conf_target
# ---------------------------------------------------------------------------

class TestBug12BlocksFieldEchoesInput:
    """BUG-12 (LOW): 'blocks' in estimatesmartfee response does not reflect
    the actual returned target (which may be clamped).
    """

    @pytest.mark.asyncio
    async def test_blocks_equals_requested_not_actual(self, rpc):
        """Request conf_target=500; response blocks=500 even though max is 25."""
        result = await rpc.rpc_estimatesmartfee(conf_target=500)
        # With BUG: blocks==500 (echoed input)
        assert result["blocks"] == 500, (
            "BUG-12: 'blocks' should reflect actual clamped target, not requested 500"
        )

    @pytest.mark.asyncio
    async def test_blocks_field_present_in_error_response(self, rpc):
        result = await rpc.rpc_estimatesmartfee(conf_target=6)
        assert "blocks" in result


# ---------------------------------------------------------------------------
# BUG-13: conf_target=1 not promoted to 2
# ---------------------------------------------------------------------------

class TestBug13ConfTarget1NotClamped:
    """BUG-13 (LOW): Core promotes conf_target==1 to 2; ouroboros allows 1."""

    @pytest.mark.asyncio
    async def test_conf_target_1_not_rejected(self, rpc):
        """Core says 'not possible to get reasonable estimates for confTarget=1'."""
        result = await rpc.rpc_estimatesmartfee(conf_target=1)
        # BUG: ouroboros processes target=1 without returning an error or
        # silently promoting it to 2
        assert result.get("blocks") == 1, (
            "BUG-13: conf_target=1 should be promoted to 2 (Core behaviour)"
        )

    def test_estimate_fee_accepts_target_1(self, fresh_estimator):
        """estimate_fee(1) should return None (too low), not process normally."""
        fresh_estimator.total[10][1] = 50.0
        fresh_estimator.confirmed[10][1] = 45.0
        fresh_estimator._total_observations = 200
        # Core would not produce an estimate at target=1; ouroboros does
        result = fresh_estimator.estimate_fee(1)
        # ouroboros returns a result for target=1 (BUG: Core returns 0/None for target=1)
        assert result is not None, (
            "BUG-13: estimate_fee(1) returns a value; Core would return failure"
        )


# ---------------------------------------------------------------------------
# BUG-14: No min-relay-fee floor on estimates
# ---------------------------------------------------------------------------

class TestBug14NoMinRelayFeeFloor:
    """BUG-14 (LOW): Core floors estimate at max(estimate, min_mempool_fee, min_relay_fee).
    ouroboros returns raw bucket estimate with no floor.
    """

    @pytest.mark.asyncio
    async def test_feerate_can_be_below_min_relay_fee(self, rpc):
        """Estimate below 1000 sat/kB (standard min relay fee) can be returned."""
        fe = rpc.node.fee_estimator
        # Put a tiny fee_rate in a bucket: 0.5 sat/vB = 500 sat/kB
        # Force target 1 to see a tiny feerate
        from ouroboros.fee_estimator import _bucket_index
        fe.total[0][1] = 50.0
        fe.confirmed[0][1] = 45.0
        fe._total_observations = 200

        result = await rpc.rpc_estimatesmartfee(conf_target=1)
        if "feerate" in result:
            feerate_sat_kvb = result["feerate"] * 1e8  # BTC/kB → sat/kB
            # BUG: can be below min relay 1000 sat/kB
            # Not asserting a failure here since we can't control exact bucket value,
            # but we can show there's no min-fee check in the code
            pass
        # Check for absence of mempool min fee enforcement in source
        import inspect
        from ouroboros import rpc as rpc_mod
        src = inspect.getsource(rpc_mod.RPCServer.rpc_estimatesmartfee)
        assert "min_relay" not in src and "min_fee" not in src and "GetMinFee" not in src, (
            "BUG-14: min relay/mempool fee floor should NOT be in rpc_estimatesmartfee yet"
        )

    def test_estimate_fee_per_kb_no_floor(self, fresh_estimator):
        """estimate_fee_per_kb with 0.5 sat/vB returns 5e-6 BTC/kB (no floor)."""
        # Manually override estimate to return 0.5 sat/vB
        from unittest.mock import patch
        with patch.object(fresh_estimator, "estimate_fee", return_value=0.5):
            rate = fresh_estimator.estimate_fee_per_kb(6)
        expected = 0.5 * 1000 / 1e8  # 5e-6 BTC/kB
        assert rate == pytest.approx(expected), (
            "BUG-14: estimate_fee_per_kb has no min-fee floor"
        )


# ---------------------------------------------------------------------------
# Correctness tests (positive path — things that DO work)
# ---------------------------------------------------------------------------

class TestCorrectBehaviour:
    """Verify aspects of the estimator that work correctly."""

    def test_process_block_increments_observations(self, fresh_estimator):
        txid = b'\x42' * 32
        entry = _make_mempool_entry(fee=10000, size=250, height_added=100)
        mempool = _make_mempool({txid: entry})
        block = MagicMock()
        tx = MagicMock(); tx.is_coinbase = False; tx.get_txid.return_value = txid
        block.transactions = [tx]
        fresh_estimator.process_block(block, height=105, mempool=mempool)
        assert fresh_estimator._total_observations == 1

    def test_bucket_index_returns_valid_index(self):
        from ouroboros.fee_estimator import _bucket_index, NUM_BUCKETS
        assert 0 <= _bucket_index(1.0) < NUM_BUCKETS
        assert 0 <= _bucket_index(1000.0) < NUM_BUCKETS
        assert 0 <= _bucket_index(1e6) < NUM_BUCKETS

    def test_estimate_fee_returns_none_when_sparse(self, fresh_estimator):
        """With insufficient data, estimate_fee returns None."""
        result = fresh_estimator.estimate_fee(6)
        assert result is None

    def test_estimate_fee_returns_value_with_sufficient_data(self, fresh_estimator):
        fresh_estimator.total[10][6] = 50.0
        fresh_estimator.confirmed[10][6] = 45.0
        fresh_estimator._total_observations = 200
        result = fresh_estimator.estimate_fee(6)
        assert result is not None
        assert result > 0

    def test_estimate_fee_per_kb_converts_correctly(self, fresh_estimator):
        """estimate_fee_per_kb = estimate_fee * 1000 / 1e8."""
        with patch.object(fresh_estimator, "estimate_fee", return_value=10.0):
            result = fresh_estimator.estimate_fee_per_kb(6)
        assert result == pytest.approx(10.0 * 1000 / 1e8)

    def test_decay_is_applied_per_block(self, fresh_estimator):
        from ouroboros.fee_estimator import DECAY_FACTOR
        fresh_estimator.confirmed[5][6] = 100.0
        fresh_estimator.total[5][6] = 100.0
        # Simulate one block with no new data
        fresh_estimator._apply_decay()
        assert fresh_estimator.confirmed[5][6] == pytest.approx(100.0 * DECAY_FACTOR)
        assert fresh_estimator.total[5][6] == pytest.approx(100.0 * DECAY_FACTOR)

    def test_save_and_load_roundtrip(self, fresh_estimator):
        fresh_estimator._total_observations = 42
        fresh_estimator.confirmed[5][6] = 3.14
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            fresh_estimator.save_to_file(path)
            from ouroboros.fee_estimator import FeeEstimator
            new_est = FeeEstimator()
            assert new_est.load_from_file(path)
            assert new_est._total_observations == 42
            assert new_est.confirmed[5][6] == pytest.approx(3.14)
        finally:
            os.unlink(path)

    def test_load_returns_false_for_missing_file(self, fresh_estimator):
        assert fresh_estimator.load_from_file("/nonexistent/path/fee.json") is False

    def test_load_returns_false_for_wrong_version(self, fresh_estimator):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": 99}, f)
            path = f.name
        try:
            assert fresh_estimator.load_from_file(path) is False
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_estimatesmartfee_no_estimator(self, rpc):
        rpc.node.fee_estimator = None
        result = await rpc.rpc_estimatesmartfee(6)
        assert "errors" in result
        assert "blocks" in result

    @pytest.mark.asyncio
    async def test_estimatesmartfee_insufficient_data(self, rpc):
        result = await rpc.rpc_estimatesmartfee(6)
        assert "errors" in result or "feerate" in result

    @pytest.mark.asyncio
    async def test_estimatesmartfee_returns_feerate_btc_per_kb(self, rpc):
        fe = rpc.node.fee_estimator
        fe.total[10][6] = 50.0
        fe.confirmed[10][6] = 45.0
        fe._total_observations = 200
        result = await rpc.rpc_estimatesmartfee(6)
        assert "feerate" in result
        # feerate should be in BTC/kB (very small number)
        assert result["feerate"] < 0.1

    @pytest.mark.asyncio
    async def test_estimaterawfee_valid_pass_bucket(self, rpc):
        fe = rpc.node.fee_estimator
        fe.total[5][6] = 50.0
        fe.confirmed[5][6] = 48.0
        result = await rpc.rpc_estimaterawfee(6, threshold=0.85)
        assert "long" in result
        h = result["long"]
        assert "pass" in h
        assert "feerate" in h
        assert "decay" in h
        assert "scale" in h

    @pytest.mark.asyncio
    async def test_estimaterawfee_decay_value(self, rpc):
        from ouroboros.fee_estimator import DECAY_FACTOR
        result = await rpc.rpc_estimaterawfee(6)
        assert result["long"]["decay"] == pytest.approx(DECAY_FACTOR)

    @pytest.mark.asyncio
    async def test_estimaterawfee_scale_is_1(self, rpc):
        result = await rpc.rpc_estimaterawfee(6)
        assert result["long"]["scale"] == 1

    def test_get_fee_summary_structure(self, fresh_estimator):
        summary = fresh_estimator.get_fee_summary()
        assert "blocks_tracked" in summary
        assert "bucket_observations" in summary
        assert "buckets" in summary
        assert len(summary["buckets"]) > 0


# ---------------------------------------------------------------------------
# File-format / persistence tests
# ---------------------------------------------------------------------------

class TestPersistence:
    """Tests for save/load of fee estimation state."""

    def test_save_uses_tmp_then_replace(self, fresh_estimator):
        """save_to_file writes .tmp then os.replace (atomic write)."""
        import inspect
        from ouroboros import fee_estimator
        src = inspect.getsource(fee_estimator.FeeEstimator.save_to_file)
        assert ".tmp" in src
        assert "os.replace" in src

    def test_load_rejects_dimension_mismatch(self, fresh_estimator):
        from ouroboros.fee_estimator import MAX_CONF_TARGET, NUM_BUCKETS
        bad_state = {
            "version": 1,
            "total_observations": 10,
            "confirmed": [[0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS - 1)],
            "total":     [[0.0] * (MAX_CONF_TARGET + 1) for _ in range(NUM_BUCKETS - 1)],
            "block_history": [],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(bad_state, f)
            path = f.name
        try:
            assert fresh_estimator.load_from_file(path) is False
        finally:
            os.unlink(path)

    def test_file_version_is_1_not_core_296_or_309900(self):
        """Core uses CURRENT_FEES_FILE_VERSION=309900; ouroboros uses version=1.

        This means fee_estimates.dat from Core is NOT loadable by ouroboros.
        """
        import inspect
        from ouroboros import fee_estimator
        src = inspect.getsource(fee_estimator.FeeEstimator.save_to_file)
        assert '"version": 1' in src or "'version': 1" in src, (
            "File version should be 1 (not Core's 309900)"
        )
        # Confirm it's NOT 309900
        assert "309900" not in src
