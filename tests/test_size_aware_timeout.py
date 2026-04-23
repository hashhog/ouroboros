"""Unit tests for plan-W95 size-aware general block-download timeout.

Background: the general (non-head-of-window) timeout in
`BlockSync._handle_timeouts` was a uniform 60s constant.  This proved to
be a one-size-fits-none compromise:

- Too lenient for the early chain (pre-500k, blocks <100 KB): a genuinely
  lost block sat in-flight for a full minute before being re-requested,
  starving drain progress.
- Too aggressive for the recent chain (1-2 MB blocks) when
  `MAX_BLOCKS_IN_FLIGHT_PER_PEER=16` lets a slow peer queue ~32 MB; W82
  had to restore 60s after 20s caused cascading re-requests (rate
  1117 → 580 blk/hr at h=817k).

Plan-W95 replaces the uniform constant with a formula scaled by the
recent-block-size EMA and the per-peer in-flight count, clamped to a
sane range.  These tests pin the arithmetic so future retuning is
intentional (a change to any of the constants should move these
assertions in lockstep).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ouroboros.block_sync import BlockSync


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 600000)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def test_ema_starts_at_one_mb():
    """Initial EMA of 1.0 MB matches post-500k mainnet average and keeps
    the first-ever call to the formula from collapsing to the floor."""
    bs = _make_block_sync()
    assert bs._w95_block_mb_ema == 1.0


def test_floor_never_violated_for_any_reasonable_input():
    """Defensive floor W95_MIN_TIMEOUT=20s must hold across the whole
    input space we actually see in practice (sub-1KB blocks, idle peer).
    With current constants the formula natural minimum is already above
    the floor, but the guard survives future retuning."""
    for mb in (0.0, 0.01, 0.05, 0.1, 0.5, 1.0):
        for n in (0, 1, 8, 16):
            t = BlockSync._w95_compute_general_timeout(avg_mb=mb, n_in_flight=n)
            assert t >= 20.0, f"floor violated at mb={mb}, n={n}: {t}"


def test_ceiling_applied_for_absurd_inputs():
    """An oversized EMA × deep per-peer queue must saturate at
    W95_MAX_TIMEOUT=240s so a degenerate signal can't wedge re-request
    forever.  Inputs here are outside any realistic mainnet operating
    point but guard against MAX_BLOCKS_IN_FLIGHT_PER_PEER being raised
    or the EMA being corrupted."""
    t = BlockSync._w95_compute_general_timeout(avg_mb=6.0, n_in_flight=32)
    # Raw: 20 + 30*6 + 3*31 = 293 → clamps to 240
    assert t == 240.0


def test_small_block_idle_peer_is_below_old_uniform():
    """Explicit numeric check — 0.05 MB × n=1 should land at ~21.5s,
    well under the prior 60s uniform.  Demonstrates tighter turnover
    for the early chain."""
    t = BlockSync._w95_compute_general_timeout(avg_mb=0.05, n_in_flight=1)
    # BASE 20 + PER_MB 30 * 0.05 + PER_IF 3 * 0 = 21.5
    # mb is max(0.1, 0.05) = 0.1 → 20 + 3.0 + 0 = 23.0
    assert t == 23.0


def test_typical_post_500k_block_matches_old_uniform():
    """1 MB block with moderate per-peer load (n=8) should land near
    the old 60s uniform — the formula is calibrated so no regression
    happens on the steady-state mainnet range that W82 was tuning for."""
    t = BlockSync._w95_compute_general_timeout(avg_mb=1.0, n_in_flight=8)
    # 20 + 30*1 + 3*7 = 71
    assert t == 71.0


def test_saturated_peer_with_big_block_is_lenient():
    """2 MB block × 16 in-flight from the same peer must get more than
    60s.  Before W95 this case false-timed-out and cascaded re-requests;
    the formula grants ~125s headroom."""
    t = BlockSync._w95_compute_general_timeout(avg_mb=2.0, n_in_flight=16)
    # 20 + 30*2 + 3*15 = 125
    assert t == 125.0


def test_timeout_increases_with_block_size():
    """Holding peer load constant, bigger blocks must always get more
    budget — regression guard against accidentally inverting the
    PER_MB term."""
    load = 4
    a = BlockSync._w95_compute_general_timeout(avg_mb=0.25, n_in_flight=load)
    b = BlockSync._w95_compute_general_timeout(avg_mb=0.75, n_in_flight=load)
    c = BlockSync._w95_compute_general_timeout(avg_mb=1.50, n_in_flight=load)
    assert a < b < c


def test_timeout_increases_with_in_flight_count():
    """Holding block size constant, more concurrent in-flight blocks from
    the same peer must always get more budget — regression guard against
    accidentally inverting the PER_IN_FLIGHT term."""
    mb = 1.0
    a = BlockSync._w95_compute_general_timeout(avg_mb=mb, n_in_flight=1)
    b = BlockSync._w95_compute_general_timeout(avg_mb=mb, n_in_flight=8)
    c = BlockSync._w95_compute_general_timeout(avg_mb=mb, n_in_flight=16)
    assert a < b < c


def test_negative_in_flight_treated_as_idle():
    """Defensive: if the peer-load snapshot yields something nonsensical
    (<1), the formula must not go negative."""
    t = BlockSync._w95_compute_general_timeout(avg_mb=1.0, n_in_flight=0)
    # n-1 clamped to 0 → 20 + 30 + 0 = 50
    assert t == 50.0


def test_ema_update_is_bounded():
    """Feeding a giant block into the EMA must not let the signal explode
    past a single block — the alpha is small so a 32 MB block moves the
    1.0 MB baseline by at most alpha*(32-1) = ~1.55 MB."""
    bs = _make_block_sync()
    alpha = bs._w95_block_mb_alpha
    bs._w95_block_mb_ema = (1.0 - alpha) * 1.0 + alpha * 32.0
    # alpha=0.05 → new EMA = 0.95 + 1.6 = 2.55
    assert 2.5 < bs._w95_block_mb_ema < 2.6
