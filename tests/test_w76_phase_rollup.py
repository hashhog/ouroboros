"""Unit tests for the W76-PHASE cross-impl phase-table rollup.

Background: each of the 10 impls ships a 500-1000 block phase probe so
we can compare where time goes during IBD.  Blockbrew splits
ConnectBlock into pre/first/script/persist; ouroboros's Python driver
sees three coarser phases (deserialize/validate/connect) because the
Rust FFI runs validate + script verification as one opaque call.

These tests exercise `_w76_record_phases` in isolation so we can assert
the accumulator, the emit format, and the reset semantics without
spinning a full drain loop.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from ouroboros.block_sync import BlockSync


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 600000)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def test_rollup_fields_initialised_to_zero():
    bs = _make_block_sync()
    assert bs._w76_blocks == 0
    assert bs._w76_deserialize_sum_ns == 0
    assert bs._w76_validate_sum_ns == 0
    assert bs._w76_connect_sum_ns == 0
    assert bs._w76_deserialize_max_ns == 0
    assert bs._w76_validate_max_ns == 0
    assert bs._w76_connect_max_ns == 0
    assert bs._w76_log_every == 1000


def test_below_threshold_does_not_emit(caplog):
    """999 recordings should not emit a rollup line."""
    bs = _make_block_sync()
    with caplog.at_level(logging.INFO):
        for _ in range(999):
            bs._w76_record_phases(100_000, 200_000, 300_000)
    w76 = [r for r in caplog.records if "[W76-PHASE]" in r.getMessage()]
    assert w76 == []
    assert bs._w76_blocks == 999
    assert bs._w76_deserialize_sum_ns == 999 * 100_000


def test_emits_and_resets_on_1000th(caplog):
    """1000th recording emits one line and zeroes the counters."""
    bs = _make_block_sync()
    # Steady 1ms/2ms/3ms phases → avg 1.0/2.0/3.0, max 1/2/3.
    with caplog.at_level(logging.INFO):
        for _ in range(1000):
            bs._w76_record_phases(1_000_000, 2_000_000, 3_000_000)
    w76 = [r for r in caplog.records if "[W76-PHASE]" in r.getMessage()]
    assert len(w76) == 1
    msg = w76[0].getMessage()
    assert "blocks=1000" in msg
    assert "deserialize_avg_ms=1.0" in msg
    assert "deserialize_max_ms=1" in msg
    assert "validate_avg_ms=2.0" in msg
    assert "validate_max_ms=2" in msg
    assert "connect_avg_ms=3.0" in msg
    assert "connect_max_ms=3" in msg
    assert "total_avg_ms=6.0" in msg
    # All counters back to pristine.
    assert bs._w76_blocks == 0
    assert bs._w76_deserialize_sum_ns == 0
    assert bs._w76_validate_sum_ns == 0
    assert bs._w76_connect_sum_ns == 0
    assert bs._w76_deserialize_max_ns == 0
    assert bs._w76_validate_max_ns == 0
    assert bs._w76_connect_max_ns == 0


def test_max_tracks_per_phase_independently(caplog):
    """The max of each phase is tracked independently of the others;
    one slow deserialize in an otherwise steady window should raise
    deserialize_max_ms without touching validate/connect_max_ms."""
    bs = _make_block_sync()
    with caplog.at_level(logging.INFO):
        # 999 steady blocks.
        for _ in range(999):
            bs._w76_record_phases(1_000_000, 2_000_000, 3_000_000)
        # One outlier: very slow deserialize, normal others.
        bs._w76_record_phases(50_000_000, 2_000_000, 3_000_000)
    w76 = [r for r in caplog.records if "[W76-PHASE]" in r.getMessage()]
    assert len(w76) == 1
    msg = w76[0].getMessage()
    assert "deserialize_max_ms=50" in msg
    assert "validate_max_ms=2" in msg
    assert "connect_max_ms=3" in msg


def test_zero_total_does_not_divide_by_zero(caplog):
    """If every recorded phase is 0ns (shouldn't happen in practice but
    mock/test paths can hit it), the blk/hr computation must not raise."""
    bs = _make_block_sync()
    with caplog.at_level(logging.INFO):
        for _ in range(1000):
            bs._w76_record_phases(0, 0, 0)
    w76 = [r for r in caplog.records if "[W76-PHASE]" in r.getMessage()]
    assert len(w76) == 1
    assert "total_avg_ms=0.0" in w76[0].getMessage()
