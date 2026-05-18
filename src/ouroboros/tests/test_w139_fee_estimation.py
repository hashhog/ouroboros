"""W139 — Fee estimation engine (`CBlockPolicyEstimator`) audit (ouroboros).

DISCOVERY wave. 30 gates audited against
  bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
    - TxConfirmStats::Record                @ 217-229
    - TxConfirmStats::UpdateMovingAverages  @ 231-242
    - TxConfirmStats::EstimateMedianVal     @ 245-409
    - TxConfirmStats::removeTx              @ 485-520
    - processTransaction                    @ 596-639
    - processBlock                          @ 669-716
    - estimateRawFee                        @ 727-761
    - estimateCombinedFee                   @ 808-842
    - estimateConservativeFee               @ 847-862
    - estimateSmartFee                      @ 871-956
    - Write / Read                          @ 978-1062
    - FlushUnconfirmed                      @ 1064-1076
    - FeeFilterRounder + MakeFeeSet         @ 1085-1119
  bitcoin-core/src/policy/feerate.{cpp,h}
  bitcoin-core/src/rpc/fees.cpp
    - estimatesmartfee                      @ 32-95
    - estimaterawfee                        @ 97-216

Scope: fee estimation is **policy code, not consensus code**, and is
Python-only in ouroboros: `src/ouroboros/fee_estimator.py` is the entire
estimator, with `block_sync.py:1349-1353` feeding it from confirmed
blocks and `rpc.py` exposing `estimatesmartfee` / `estimaterawfee`. The
Rust pipeline (`ferrous-utils/sync/`) has zero fee-estimation surface
— see G30 architectural guard.

This file contains one xfail per BUG-marked gate; xfails flip to XPASS
the moment a fix lands.  PRESENT gates are plain asserts that pin
Core-parity behaviour (G1, G2, G3, G6 from the W114 close, the partial
gates, plus G28 `FeeFilterRounder` and the G30 two-pipeline guard).

Reference: `ouroboros/audit/w139_fee_estimation.md`.

NO production code changes.  Only audit + xfail.
"""

from __future__ import annotations

import inspect
import re
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup + sync module mock so ouroboros imports cleanly without the
# compiled Rust extension being present.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# ===========================================================================
# G1-G6 — Constants & data structures
# ===========================================================================


def test_w139_g1_decay_constants_present() -> None:
    """G1: SHORT/MED/LONG decay 0.962/0.9952/0.99931.

    Core: block_policy_estimator.h:163-167 — SHORT_DECAY=.962,
    MED_DECAY=.9952, LONG_DECAY=.99931.

    PRESENT — W114 BUG-1 fix landed; DECAY dict populated.
    """
    from ouroboros.fee_estimator import DECAY, Horizon

    assert DECAY[Horizon.SHORT] == pytest.approx(0.962, rel=1e-4)
    assert DECAY[Horizon.MEDIUM] == pytest.approx(0.9952, rel=1e-4)
    assert DECAY[Horizon.LONG] == pytest.approx(0.99931, rel=1e-5)


def test_w139_g2_scale_constants_present() -> None:
    """G2: SHORT/MED/LONG scale 1/2/24.

    Core: block_policy_estimator.h:152-158.

    PRESENT.
    """
    from ouroboros.fee_estimator import SCALE, Horizon

    assert SCALE[Horizon.SHORT] == 1
    assert SCALE[Horizon.MEDIUM] == 2
    assert SCALE[Horizon.LONG] == 24


def test_w139_g3_period_counts_present() -> None:
    """G3: SHORT/MED/LONG periods 12/24/42.

    Core: block_policy_estimator.h:151-158.

    PRESENT.
    """
    from ouroboros.fee_estimator import PERIODS, Horizon

    assert PERIODS[Horizon.SHORT] == 12
    assert PERIODS[Horizon.MEDIUM] == 24
    assert PERIODS[Horizon.LONG] == 42


@pytest.mark.xfail(
    reason="W139 BUG-13 (P1): ouroboros uses 24 hand-coded sat/vB bucket "
           "boundaries vs Core's ~237 exponentially-spaced sat/kvB buckets "
           "(MIN_BUCKET_FEERATE=100, MAX_BUCKET_FEERATE=1e7, FEE_SPACING=1.05). "
           "MIN_BUCKET_FEERATE / MAX_BUCKET_FEERATE / FEE_SPACING constants "
           "are entirely absent from fee_estimator.py.",
    strict=True,
)
def test_w139_g4_min_max_spacing_constants_present() -> None:
    """G4: MIN_BUCKET_FEERATE=100, MAX_BUCKET_FEERATE=1e7, FEE_SPACING=1.05.

    Core: block_policy_estimator.h:190-198.
    """
    from ouroboros import fee_estimator

    assert hasattr(fee_estimator, "MIN_BUCKET_FEERATE")
    assert hasattr(fee_estimator, "MAX_BUCKET_FEERATE")
    assert hasattr(fee_estimator, "FEE_SPACING")
    assert fee_estimator.MIN_BUCKET_FEERATE == 100
    assert fee_estimator.MAX_BUCKET_FEERATE == 1e7
    assert fee_estimator.FEE_SPACING == pytest.approx(1.05)


@pytest.mark.xfail(
    reason="W139 BUG-13 (P1): NUM_BUCKETS=24 hand-coded; Core layout would "
           "produce ~237 buckets.  Cross-impl bucket-membership of any given "
           "feerate will differ structurally from Core.",
    strict=True,
)
def test_w139_g5_bucket_count_matches_core_237() -> None:
    """G5: NUM_BUCKETS ~ 237.

    Core builds buckets by iterating MIN→MAX at FEE_SPACING multiplier.
    """
    from ouroboros.fee_estimator import NUM_BUCKETS

    # Allow ±5 slack for impl latitude; Core's exact count depends on
    # whether the final boundary is rounded up.
    assert 230 <= NUM_BUCKETS <= 245, (
        f"NUM_BUCKETS={NUM_BUCKETS} — expected ~237 (Core exponential ladder)"
    )


def test_w139_g6_max_conf_target_1008() -> None:
    """G6: MAX_CONF_TARGET=1008 (Core LONG horizon: 42 periods × scale 24).

    PRESENT — W114 BUG-2 fix landed.
    """
    from ouroboros.fee_estimator import MAX_CONF_TARGET

    assert MAX_CONF_TARGET == 1008


# ===========================================================================
# G7-G11 — estimateSmartFee algorithm
# ===========================================================================


@pytest.mark.xfail(
    reason="W139 BUG-2 + BUG-15 (P1): estimate_fee uses a single "
           "SUCCESS_THRESHOLD=0.85 path; Core's HALF_SUCCESS_PCT=0.6 at "
           "confTarget/2 is absent.",
    strict=True,
)
def test_w139_g7_half_sub_estimate_at_half_target() -> None:
    """G7: HALF sub-estimate at confTarget/2, threshold 0.60.

    Core: estimateSmartFee@919 — `double halfEst = estimateCombinedFee(
    confTarget/2, HALF_SUCCESS_PCT, ...)`.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    # Look for the HALF_SUCCESS_PCT=0.6 constant or any reference to a
    # half-target sub-estimate.
    assert "HALF_SUCCESS_PCT" in src or "0.6" in src, (
        "Half-success-percent threshold 0.6 missing"
    )
    assert "confTarget/2" in src or "conf_target // 2" in src or (
        "halfEst" in src
    ), "estimate_fee does not include HALF sub-estimate at confTarget/2"


def test_w139_g8_full_sub_estimate_threshold_085() -> None:
    """G8: FULL sub-estimate at confTarget, threshold 0.85.

    PARTIAL — `_estimate_from_buckets` uses 0.85 but as a single-target
    direct path, not the 3-sub-estimate max.  BUG-17 (no cross-horizon
    checkShorterHorizon fallback).  This test passes because the
    threshold value is right; BUG-17 is a separate gate (G10).
    """
    from ouroboros.fee_estimator import SUCCESS_THRESHOLD

    assert SUCCESS_THRESHOLD == pytest.approx(0.85), (
        f"SUCCESS_THRESHOLD={SUCCESS_THRESHOLD} — expected 0.85 (Core SUCCESS_PCT)"
    )


@pytest.mark.xfail(
    reason="W139 BUG-2 + BUG-15 + BUG-16 (P1): DOUBLE sub-estimate at "
           "2*confTarget with threshold 0.95 is absent. Core's "
           "estimateConservativeFee cross-horizon walk also missing.",
    strict=True,
)
def test_w139_g9_double_sub_estimate_at_2x_target() -> None:
    """G9: DOUBLE sub-estimate at 2×confTarget, threshold 0.95.

    Core: estimateSmartFee@933 — `double doubleEst = estimateCombinedFee(
    2 * confTarget, DOUBLE_SUCCESS_PCT, ...)`.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    assert "DOUBLE_SUCCESS_PCT" in src or "0.95" in src, (
        "DOUBLE_SUCCESS_PCT=0.95 missing"
    )
    assert "doubleEst" in src or "2 * confTarget" in src or (
        "2*confTarget" in src or "2*conf_target" in src
    ), "estimate_fee does not include DOUBLE sub-estimate at 2×confTarget"


@pytest.mark.xfail(
    reason="W139 BUG-2 (P1-CDIV): estimate_fee returns a single-target "
           "lookup; Core returns max(HALF, FULL, DOUBLE) plus conservative. "
           "Missing the monotonic-fee safeguard.",
    strict=True,
)
def test_w139_g10_max_of_three_sub_estimates_returned() -> None:
    """G10: estimateSmartFee returns max(HALF, FULL, DOUBLE).

    Core: estimateSmartFee@925-940 — the median is set to max of the
    three.  Without it, estimate(2) might exceed estimate(6).
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator.estimate_fee)
    # Look for the canonical 3-sub-estimate shape: three sub-estimates
    # combined with max().  The threshold-constants HALF/FULL/DOUBLE are
    # required because BUG-15 currently leaves only one threshold (0.85).
    has_three_thresholds = (
        "HALF_SUCCESS_PCT" in src and "DOUBLE_SUCCESS_PCT" in src
    )
    has_three_sub_estimates = (
        ("halfEst" in src or "half_est" in src)
        and ("doubleEst" in src or "double_est" in src)
        and "max(" in src
    )
    assert has_three_thresholds or has_three_sub_estimates, (
        "estimate_fee does not appear to compute the 3-sub-estimate max "
        "(HALF + FULL + DOUBLE)"
    )


@pytest.mark.xfail(
    reason="W139 BUG-3 (P1): rpc_estimatesmartfee accepts `estimate_mode` "
           "('economical'/'conservative'/'unset') but never passes it down. "
           "Conservative mode is a silent no-op.",
    strict=True,
)
def test_w139_g11_conservative_mode_plumbed_from_rpc() -> None:
    """G11: estimate_mode='conservative' flips a conservative flag that
    reaches estimateConservativeFee.

    Core: rpc/fees.cpp:80 — `bool conservative{fee_mode ==
    FeeEstimateMode::CONSERVATIVE}` plumbed through.
    """
    src = _read_py("rpc.py")
    # The estimator API must accept a conservative kwarg.
    from ouroboros.fee_estimator import FeeEstimator

    sig = inspect.signature(FeeEstimator.estimate_fee)
    params = set(sig.parameters)
    # Either explicit `conservative` kwarg or an `estimate_mode` kwarg.
    assert "conservative" in params or "estimate_mode" in params, (
        "FeeEstimator.estimate_fee accepts no conservative/estimate_mode kwarg"
    )
    # And the RPC must pass it through.
    rpc_estimate_smart_match = re.search(
        r"def rpc_estimatesmartfee.*?\n([\s\S]*?)\n    async def ",
        src,
    )
    assert rpc_estimate_smart_match, "Could not locate rpc_estimatesmartfee"
    body = rpc_estimate_smart_match.group(1)
    assert (
        "conservative=" in body
        or "estimate_mode=" in body
        or "estimate_mode" in body
    ), "rpc_estimatesmartfee does not plumb conservative/estimate_mode"


# ===========================================================================
# G12-G18 — EstimateMedianVal algorithm
# ===========================================================================


@pytest.mark.xfail(
    reason="W139 BUG-15 (P1): only SUCCESS_THRESHOLD=0.85 exists. Core has "
           "three thresholds — HALF=0.6, FULL=0.85, DOUBLE=0.95.",
    strict=True,
)
def test_w139_g12_three_success_thresholds() -> None:
    """G12: three success-threshold constants.

    Core: block_policy_estimator.h:170-174 — HALF_SUCCESS_PCT=.6,
    SUCCESS_PCT=.85, DOUBLE_SUCCESS_PCT=.95.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    # Check for either the constants or numeric literals nearby.
    assert "HALF_SUCCESS_PCT" in src, "HALF_SUCCESS_PCT=0.6 constant missing"
    assert "DOUBLE_SUCCESS_PCT" in src, "DOUBLE_SUCCESS_PCT=0.95 constant missing"


@pytest.mark.xfail(
    reason="W139 BUG-14 (P1): no per-bucket sufficient-txs gate. "
           "_estimate_from_buckets requires only `total >= 2.0` per bucket, "
           "vs Core's merge-buckets-until ≥ sufficientTxVal/(1-decay).",
    strict=True,
)
def test_w139_g13_sufficient_feetxs_merge_threshold() -> None:
    """G13: SUFFICIENT_FEETXS=0.1 / SUFFICIENT_TXS_SHORT=0.5 — bucket-merge
    threshold of `sufficientTxVal / (1 - decay)` average txs.

    Core: block_policy_estimator.h:177-179 + estimateMedianVal@298.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    assert "SUFFICIENT_FEETXS" in src, "SUFFICIENT_FEETXS=0.1 constant missing"
    assert "SUFFICIENT_TXS_SHORT" in src, (
        "SUFFICIENT_TXS_SHORT=0.5 constant missing"
    )


@pytest.mark.xfail(
    reason="W139 BUG-4 (P1): no process_transaction admission hook. "
           "Mempool never notifies fee_estimator on add — no per-tx bucket "
           "tracking, no mapMemPoolTxs equivalent.",
    strict=True,
)
def test_w139_g14_process_transaction_admission_hook() -> None:
    """G14: processTransaction admission hook called from mempool add.

    Core: validation.cpp wires CBlockPolicyEstimator as a
    CValidationInterface listener; processTransaction is called on
    every TransactionAddedToMempool.
    """
    from ouroboros.fee_estimator import FeeEstimator

    estimator = FeeEstimator()
    # Either snake_case or camelCase admission method.
    assert hasattr(estimator, "process_transaction") or hasattr(
        estimator, "processTransaction"
    ), "FeeEstimator has no per-tx admission hook"
    # And the mempool source must call it.
    src_node = _read_py("node.py")
    src_mempool = _read_py("mempool.py")
    has_wire = (
        "fee_estimator.process_transaction" in src_node
        or "fee_estimator.process_transaction" in src_mempool
        or "on_tx_added" in src_mempool
    )
    assert has_wire, (
        "fee_estimator.process_transaction not wired from mempool admission"
    )


@pytest.mark.xfail(
    reason="W139 BUG-4 (P1): no unconfTxs circular buffer → no extraNum "
           "term in EstimateMedianVal. Estimates blind to mempool backlog.",
    strict=True,
)
def test_w139_g15_extra_num_from_unconf_txs() -> None:
    """G15: EstimateMedianVal's `extraNum` term tracks unconfirmed mempool
    txs per bucket via the unconfTxs[blockIndex][bucket] ring buffer.

    Core: estimateMedianVal@290-291 — extraNum sums over the entire
    range past confTarget.
    """
    from ouroboros.fee_estimator import FeeEstimator

    estimator = FeeEstimator()
    assert hasattr(estimator, "unconf_txs") or hasattr(estimator, "unconfTxs"), (
        "FeeEstimator has no unconfTxs ring buffer"
    )


@pytest.mark.xfail(
    reason="W139 BUG-5 (P1): no remove_tx method, no fail_avg array. "
           "Mempool evictions of unconfirmed txs are invisible to the "
           "estimator → failNum term always zero.",
    strict=True,
)
def test_w139_g16_remove_tx_records_to_fail_avg() -> None:
    """G16: removeTx records evicted-but-unconfirmed txs into failAvg.

    Core: removeTx@485-520 — increments failAvg[period][bucket] when
    blocksAgo >= scale.
    """
    from ouroboros.fee_estimator import FeeEstimator

    estimator = FeeEstimator()
    assert hasattr(estimator, "remove_tx") or hasattr(estimator, "removeTx"), (
        "FeeEstimator has no remove_tx method"
    )
    assert hasattr(estimator, "fail_avg") or hasattr(estimator, "failAvg") or (
        hasattr(estimator, "short_fails")
        and hasattr(estimator, "med_fails")
        and hasattr(estimator, "long_fails")
    ), "FeeEstimator has no fail_avg array"


@pytest.mark.xfail(
    reason="W139 BUG-5 (P1): _estimate_from_buckets does not use failAvg "
           "data (because failAvg is absent). failNum term in success-rate "
           "denominator is always zero.",
    strict=True,
)
def test_w139_g17_fail_num_term_present_in_estimate() -> None:
    """G17: EstimateMedianVal's `failNum` term flows from failAvg into
    the curPct denominator.

    Core: estimateMedianVal@289, @305 — curPct = nConf / (totalNum +
    failNum + extraNum).
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator)
    # Look for any of failNum, fail_num, fail_avg used in the estimator.
    assert ("failNum" in src or "fail_num" in src or "fail_avg" in src), (
        "estimateMedianVal's failNum-equivalent absent from FeeEstimator"
    )


@pytest.mark.xfail(
    reason="W139 BUG-6 (P1): no ClearCurrent ring-buffer roll. Knock-on "
           "from BUG-4 (no unconfTxs).",
    strict=True,
)
def test_w139_g18_clear_current_ring_buffer_roll() -> None:
    """G18: processBlock calls ClearCurrent to roll the unconfTxs ring.

    Core: processBlock@687-690 — feeStats/shortStats/longStats.ClearCurrent(
    nBlockHeight).
    """
    from ouroboros.fee_estimator import FeeEstimator

    estimator = FeeEstimator()
    assert hasattr(estimator, "clear_current") or hasattr(
        estimator, "ClearCurrent"
    ), "FeeEstimator has no clear_current ring-roll method"


# ===========================================================================
# G19-G22 — processBlock pipeline
# ===========================================================================


def test_w139_g19_decay_before_record_in_process_block() -> None:
    """G19: decay applied BEFORE recording new block data (PARTIAL — order
    is correct but BUG-7 still over-decays the unconfirmed denominator).

    Core: processBlock@687-695 — ClearCurrent → UpdateMovingAverages
    (decay) → processBlockTx (record).
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator.process_block)
    # Find the line index where _apply_decay is called vs _record_confirmation.
    decay_idx = src.find("_apply_decay")
    record_idx = src.find("_record_confirmation")
    assert decay_idx > 0
    assert record_idx > 0
    assert decay_idx < record_idx, (
        "process_block calls _record_confirmation BEFORE _apply_decay — "
        "decay must precede new observations"
    )


@pytest.mark.xfail(
    reason="W139 BUG-8 (P1): blocks_to_confirm = height - entry_height + 1 "
           "(off-by-one). Core: blocksToConfirm = nBlockHeight - txHeight "
           "(no +1). A tx mined in the next block records btc=2 instead of 1.",
    strict=True,
)
def test_w139_g20_blocks_to_confirm_no_off_by_one() -> None:
    """G20: blocks_to_confirm formula matches Core (no `+1`).

    Core: processBlockTx@652 — `int blocksToConfirm = nBlockHeight -
    tx.info.txHeight;` (1-based; tx mined in next block → btc=1).
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator.process_block)
    # The literal `+1` after the height subtraction is the bug shape.
    has_off_by_one = (
        "height - entry_height + 1" in src
        or "height_added + 1" in src
        or "blocks_to_confirm = height - entry_height + 1" in src
    )
    assert not has_off_by_one, (
        "BUG-8: drop the +1 from blocks_to_confirm formula"
    )


@pytest.mark.xfail(
    reason="W139 BUG-18 (P1): rpc_estimatesmartfee returns `blocks` always "
           "echoing the requested conf_target.  Core clamps to "
           "MaxUsableEstimate and returns the clamped value as "
           "feeCalc.returnedTarget.",
    strict=True,
)
def test_w139_g21_blocks_reflects_max_usable_estimate() -> None:
    """G21: `blocks` in estimatesmartfee response = feeCalc.returnedTarget,
    NOT the raw request.

    Core: estimateSmartFee@896 — `feeCalc.returnedTarget = confTarget;`
    AFTER clamping by MaxUsableEstimate.
    """
    src = _read_py("rpc.py")
    # The RPC body should compute a clamped target and use that value
    # for the response 'blocks' field.
    rpc_match = re.search(
        r"async def rpc_estimatesmartfee[\s\S]*?return\s*\{",
        src,
    )
    assert rpc_match is not None, "Could not find rpc_estimatesmartfee body"
    body = rpc_match.group(0)
    # Look for a max_usable_estimate / MaxUsableEstimate reference.
    assert (
        "max_usable" in body.lower()
        or "MaxUsableEstimate" in body
        or "returned_target" in body
    ), "rpc_estimatesmartfee does not clamp 'blocks' to MaxUsableEstimate"


@pytest.mark.xfail(
    reason="W139 BUG-1 (P0-CDIV): estimate_fee_per_kb comment says BTC/kB "
           "but returns BTC/kvB; estimate_fee returns sat/vB. Downstream "
           "callers (wallet sends in rpc.py:9009-9015) use the raw sat/vB "
           "return inconsistently. Pick one unit and document.",
    strict=True,
)
def test_w139_g22_fee_units_consistent_across_estimator_api() -> None:
    """G22: estimate_fee and estimate_fee_per_kb agree on unit conventions.

    Core's wire convention: integer sat/kvB internally; BTC/kvB only at
    the RPC JSON output boundary.
    """
    from ouroboros import fee_estimator

    src_per_kb = inspect.getsource(fee_estimator.FeeEstimator.estimate_fee_per_kb)
    # The docstring/comment should not mislabel BTC/kB.
    # When fixed, the conversion comment should explicitly say BTC/kvB
    # (kilo-virtual-byte), not just BTC/kB.
    assert "BTC/kvB" in src_per_kb or "BTC/1000vB" in src_per_kb, (
        "estimate_fee_per_kb comment/docstring uses 'BTC/kB' but Core's "
        "convention is BTC/kvB. Cosmetic but propagates to wallet callers."
    )


# ===========================================================================
# G23-G26 — Persistence
# ===========================================================================


@pytest.mark.xfail(
    reason="W139 BUG-9 (P1): load_from_file accepts stale files. Core "
           "refuses files older than MAX_FILE_AGE=60h unless "
           "read_stale_estimates=true.",
    strict=True,
)
def test_w139_g23_stale_file_age_gate_on_load() -> None:
    """G23: load_from_file rejects files older than MAX_FILE_AGE=60h.

    Core: block_policy_estimator.cpp:567-576 — GetFeeEstimatorFileAge()
    + early-return when file_age > MAX_FILE_AGE.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator.load_from_file)
    # The fix would reference MAX_FILE_AGE or os.path.getmtime / file_age.
    assert (
        "MAX_FILE_AGE" in src
        or "getmtime" in src
        or "file_age" in src
        or "stat_result" in src
    ), "load_from_file does not gate on file age"


@pytest.mark.xfail(
    reason="W139 BUG-10 (P1): no periodic flush. Core writes "
           "fee_estimates.dat every FEE_FLUSH_INTERVAL=1h via the kernel "
           "scheduler. ouroboros only persists on clean shutdown.",
    strict=True,
)
def test_w139_g24_periodic_flush_loop() -> None:
    """G24: periodic 1h flush of fee_estimates.json to survive crashes.

    Core: block_policy_estimator.h:26 — FEE_FLUSH_INTERVAL=1h driven by
    the kernel scheduler.
    """
    src_node = _read_py("node.py")
    src_fee = _read_py("fee_estimator.py")
    combined = src_node + src_fee
    # The marker must be one of:
    #  - the Core-named constant FEE_FLUSH_INTERVAL (preferred);
    #  - an explicit "flush_loop" / "fee_estimator_flush_task" function;
    #  - or a periodic-tasks function whose body actually calls
    #    fee_estimator.save_to_file.
    has_constant = "FEE_FLUSH_INTERVAL" in combined
    has_named_task = (
        "flush_loop" in combined or "fee_estimator_flush" in combined
    )
    # Locate the _periodic_tasks function and check it contains a save.
    periodic_match = re.search(
        r"async def _periodic_tasks[\s\S]*?(?=\n    async def |\nclass )",
        src_node,
    )
    periodic_body = periodic_match.group(0) if periodic_match else ""
    has_save_in_periodic = (
        "fee_estimator.save_to_file" in periodic_body
        or "self.fee_estimator.save_to_file" in periodic_body
    )
    assert has_constant or has_named_task or has_save_in_periodic, (
        "No periodic flush of fee_estimates.json: FEE_FLUSH_INTERVAL "
        "constant absent, no flush_loop task, and _periodic_tasks does "
        "not call fee_estimator.save_to_file"
    )


@pytest.mark.xfail(
    reason="W139 BUG-11 (P1): no FlushUnconfirmed shutdown hook. Knock-on "
           "from BUG-4 + BUG-5 (no process_transaction → no tracked-tx "
           "map to flush).",
    strict=True,
)
def test_w139_g25_flush_unconfirmed_shutdown_hook() -> None:
    """G25: shutdown calls FlushUnconfirmed to record still-tracked mempool
    txs as removed-without-confirm.

    Core: block_policy_estimator.cpp:1064-1076 — calls _removeTx for every
    entry in mapMemPoolTxs, feeding the failAvg statistic.
    """
    from ouroboros.fee_estimator import FeeEstimator

    estimator = FeeEstimator()
    assert hasattr(estimator, "flush_unconfirmed") or hasattr(
        estimator, "FlushUnconfirmed"
    ), "FeeEstimator has no flush_unconfirmed method"


@pytest.mark.xfail(
    reason="W139 BUG-12 (P2): JSON file format diverges from Core's binary "
           "(VectorFormatter+EncodedDoubleFormatter). No CURRENT_FEES_FILE_VERSION "
           "gate, no historical-height bounds check, no bucket-range "
           "validation. Wire-format divergence — cross-impl portability nil.",
    strict=True,
)
def test_w139_g26_file_format_versioned_binary() -> None:
    """G26: persistence is versioned binary with field-level guards.

    Core: Write@978-1000 — [version:i32][nBestSeenHeight:u32]
    [firstRecordedHeight:u32][nBestSeenHeight:u32][buckets][feeStats]
    [shortStats][longStats]. Read@1002-1062 validates version is not
    newer, and rejects numBuckets outside [2,1000].
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    # Version-gate check: CURRENT_FEES_FILE_VERSION constant present.
    assert "CURRENT_FEES_FILE_VERSION" in src, (
        "Missing CURRENT_FEES_FILE_VERSION = 309900 constant"
    )
    # And the load path should track best-seen-height.
    assert "nBestSeenHeight" in src or "n_best_seen_height" in src, (
        "No nBestSeenHeight bookkeeping in persistence"
    )


# ===========================================================================
# G27-G30 — FeeFilterRounder + wiring + two-pipeline guard
# ===========================================================================


@pytest.mark.xfail(
    reason="W139 BUG-20 (P2): no static_assert that the first bucket "
           "boundary > 0. Latent footgun if future refactor inserts a 0 "
           "boundary that would silently treat fee_rate=0 as bucket 0 + "
           "trigger 0/0 division in success-rate calc.",
    strict=True,
)
def test_w139_g27_min_bucket_feerate_positive_asserted() -> None:
    """G27: MIN_BUCKET_FEERATE > 0 assertion at module-import time.

    Core: block_policy_estimator.cpp:546 — `static_assert(
    MIN_BUCKET_FEERATE > 0, "Min feerate must be nonzero");`.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator)
    # Look for an explicit module-level assert on the first boundary.
    assert (
        "assert FEE_RATE_BUCKETS[0]" in src
        or "FEE_RATE_BUCKETS[0] > 0" in src
        or "Min feerate must be nonzero" in src
    ), "Module-level positivity assert on FEE_RATE_BUCKETS[0] missing"


def test_w139_g28_fee_filter_rounder_constants_and_layout() -> None:
    """G28: FeeFilterRounder builds the FeeFilterSpacing=1.1 ladder up to
    MAX_FILTER_FEERATE=1e7, with `0` as the first boundary.

    Core: block_policy_estimator.cpp:1085-1101 — MakeFeeSet.
    BUG-19 caveat: RNG source diverges (Python random vs Core
    FastRandomContext) but the rounding ladder itself is correct.
    """
    from ouroboros.p2p import (
        FeeFilterRounder,
        FEE_FILTER_SPACING,
        MAX_FILTER_FEERATE,
    )

    assert FEE_FILTER_SPACING == pytest.approx(1.1)
    assert MAX_FILTER_FEERATE == 1e7

    # Build a rounder and inspect its internal fee_set.
    rounder = FeeFilterRounder(min_incremental_fee=1000)
    fee_set = rounder._fee_set
    assert fee_set[0] == 0, "First boundary must be 0 (Core MakeFeeSet@1092)"
    assert fee_set[-1] >= 1.0  # plus at least one populated boundary

    # The ladder steps by 1.1×; consecutive non-zero entries should be
    # ~1.1× apart.
    non_zero = [x for x in fee_set if x > 0]
    if len(non_zero) >= 2:
        ratios = [non_zero[i + 1] / non_zero[i] for i in range(len(non_zero) - 1)]
        # All ratios should be close to 1.1 (modulo the final boundary
        # which may exceed MAX_FILTER_FEERATE slightly).
        good = sum(1 for r in ratios if 1.05 < r < 1.15)
        assert good >= len(ratios) - 1, (
            "FeeFilterRounder ladder is not at FEE_FILTER_SPACING=1.1"
        )


@pytest.mark.xfail(
    reason="W139 BUG-21 (P1): process_block has no `nBlockHeight <= "
           "nBestSeenHeight` guard. Core processBlock@673-680 short-circuits "
           "side-chains/reorgs. The block_sync caller mitigates today, but "
           "submitblock RPC path can bypass.",
    strict=True,
)
def test_w139_g29_process_block_reorg_guard() -> None:
    """G29: process_block returns early if nBlockHeight <= nBestSeenHeight.

    Core: processBlock@673-680.
    """
    from ouroboros import fee_estimator

    src = inspect.getsource(fee_estimator.FeeEstimator.process_block)
    # Either an explicit early-return on height regression OR a
    # nBestSeenHeight attribute being checked.
    assert (
        "nBestSeenHeight" in src
        or "_n_best_seen_height" in src
        or "best_seen_height" in src
        or "<= self._best_height" in src
    ), "No reorg guard (nBlockHeight <= nBestSeenHeight early-return)"


def test_w139_g30_two_pipeline_fee_estimator_python_only() -> None:
    """G30 (NEW): two-pipeline guard — fee estimation lives in Python only.

    The Rust pipeline (`ferrous-utils/`) must contain ZERO fee-estimation
    code. This guard exists because:
    - Fee estimation is policy/observer code, not consensus code.
    - ouroboros's architectural split puts policy in Python, consensus in
      Rust. Future regression (e.g. moving the estimator to a Rust crate
      "for performance") trips this guard.

    Extends the guard chain W76 + W120 + W121 + W122 + W125 + W128 +
    W129 + W130 + W131 + W132 + W133 + W136 + W137 → now W139.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")

    # The Python module must still be importable as the single estimator.
    from ouroboros.fee_estimator import FeeEstimator  # noqa: F401

    # No Rust file may contain any of these fee-estimator identifiers.
    FORBIDDEN_KEYWORDS = (
        "BlockPolicyEstimator",
        "TxConfirmStats",
        "FEE_SPACING",
        "MIN_BUCKET_FEERATE",
        "MAX_BUCKET_FEERATE",
        "HALF_SUCCESS_PCT",
        "DOUBLE_SUCCESS_PCT",
        "SUFFICIENT_FEETXS",
        "estimate_smart_fee",
        "estimate_raw_fee",
        "FeeEstimator",
        "fee_estimator",
    )

    violations: list[str] = []
    for rs in FERROUS_UTILS.rglob("*.rs"):
        # Exclude test/example/benchmark trees.
        if any(part in {"tests", "examples", "benches"} for part in rs.parts):
            continue
        text = rs.read_text(encoding="utf-8", errors="replace")
        for kw in FORBIDDEN_KEYWORDS:
            # Strict literal match — guard against future regressions.
            if kw in text:
                # Allow string matches inside `//`-prefixed comments
                # (documenting that the surface is Python-only).
                for ln_no, line in enumerate(text.splitlines(), start=1):
                    if kw not in line:
                        continue
                    if line.lstrip().startswith("//"):
                        continue
                    violations.append(f"{rs}:{ln_no}: forbidden keyword {kw!r}")

    assert not violations, (
        "Two-pipeline-guard violation(s):\n"
        + "\n".join(f"  - {v}" for v in violations)
        + "\n\nFee estimation is a Python-only responsibility in ouroboros. "
        "The Rust pipeline must contain zero fee-estimator identifiers."
    )


# ===========================================================================
# Trailer: documented-divergence pin
# ===========================================================================


def test_w139_bug19_fee_filter_rounder_rng_documented_divergence() -> None:
    """BUG-19 (P2): FeeFilterRounder.round uses Python's `random.randint`
    rather than Core's FastRandomContext. Documented divergence — no fix
    needed because Core itself uses a per-instance RNG (output depends
    on seed). Network-observable behaviour is statistically equivalent.

    This is an explicit no-op test pinning the contextual note.
    """
    from ouroboros.p2p import FeeFilterRounder

    src = inspect.getsource(FeeFilterRounder)
    # Should use Python's `random` module.
    assert "random.randint" in src or "random." in src, (
        "FeeFilterRounder does not use Python's random — has the RNG "
        "source been swapped? Update the test + audit if so."
    )
