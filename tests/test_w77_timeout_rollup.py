"""Unit tests for the W77-TIMEOUT peer-timeout instrumentation.

Background: live ouroboros logs during IBD show 5-13 block requests
timing out per _handle_timeouts cycle, same peers getting re-requested,
header sync peer switching.  The per-cycle WARNING aggregates badly —
this rollup groups timeouts, failed peers, re-request distribution and
request→connect latency into one 100-block summary so operators can
tell whether peer churn is the IBD throughput ceiling.

These tests exercise `_w77_record_connect` in isolation — driving its
inputs directly so we can assert counter behaviour without spinning a
full drain loop.
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
    assert bs._w77_blocks == 0
    assert bs._w77_timeouts_total == 0
    assert bs._w77_timeout_cycles == 0
    assert bs._w77_latency_sum_s == 0.0
    assert bs._w77_latency_max_s == 0.0
    assert len(bs._w77_failed_peers) == 0
    assert len(bs._w77_rerequest_peer_counts) == 0
    assert len(bs._w77_first_request_time) == 0


def test_record_connect_below_threshold_does_not_emit(caplog):
    """99 connects should not emit a rollup line."""
    bs = _make_block_sync()
    with caplog.at_level(logging.INFO):
        for i in range(99):
            block_hash = bytes([i]) + b"\x00" * 31
            bs._w77_first_request_time[block_hash] = 1000.0
            bs._w77_record_connect(block_hash, 1001.0)
    w77 = [r for r in caplog.records if "[W77-TIMEOUT]" in r.getMessage()]
    assert w77 == []
    assert bs._w77_blocks == 99


def test_record_connect_emits_and_resets_on_100th(caplog):
    """100th connect emits one line and zeroes the counters."""
    bs = _make_block_sync()
    # Fabricate a steady 1s latency so avg and max align at 1000 ms.
    with caplog.at_level(logging.INFO):
        for i in range(100):
            block_hash = bytes([i]) + b"\x00" * 31
            bs._w77_first_request_time[block_hash] = 500.0
            bs._w77_record_connect(block_hash, 501.0)
    w77 = [r for r in caplog.records if "[W77-TIMEOUT]" in r.getMessage()]
    assert len(w77) == 1
    msg = w77[0].getMessage()
    assert "blocks=100" in msg
    assert "req_connect_avg_ms=1000.0" in msg
    assert "req_connect_max_ms=1000" in msg
    # Reset to pristine.
    assert bs._w77_blocks == 0
    assert bs._w77_latency_sum_s == 0.0
    assert bs._w77_latency_max_s == 0.0


def test_missing_first_request_treated_as_zero_latency(caplog):
    """Blocks that bypass the request map (compact-block fast path,
    pre-instrumentation replay) should neither contribute latency nor
    blow up."""
    bs = _make_block_sync()
    with caplog.at_level(logging.INFO):
        for i in range(100):
            block_hash = bytes([i]) + b"\x00" * 31
            # No first_request_time seeded.
            bs._w77_record_connect(block_hash, 999999.0)
    w77 = [r for r in caplog.records if "[W77-TIMEOUT]" in r.getMessage()]
    assert len(w77) == 1
    msg = w77[0].getMessage()
    assert "req_connect_avg_ms=0.0" in msg
    assert "req_connect_max_ms=0" in msg


def test_rollup_surfaces_timeout_and_failed_peer_state(caplog):
    """Populated timeout + failed-peer state should surface in the
    emitted line so the operator can see churn without grepping the
    per-cycle WARNING."""
    bs = _make_block_sync()
    bs._w77_timeouts_total = 150
    bs._w77_timeout_cycles = 10
    bs._w77_failed_peers = {"1.1.1.1:8333", "2.2.2.2:8333", "3.3.3.3:8333"}
    bs._w77_rerequest_peer_counts["4.4.4.4:8333"] = 40
    bs._w77_rerequest_peer_counts["5.5.5.5:8333"] = 30
    bs._w77_rerequest_peer_counts["6.6.6.6:8333"] = 20
    bs._w77_rerequest_peer_counts["7.7.7.7:8333"] = 5

    with caplog.at_level(logging.INFO):
        for i in range(100):
            bs._w77_record_connect(bytes([i]) + b"\x00" * 31, 0.0)

    w77 = [r for r in caplog.records if "[W77-TIMEOUT]" in r.getMessage()]
    assert len(w77) == 1
    msg = w77[0].getMessage()
    assert "timeouts=150" in msg
    assert "timeout_cycles=10" in msg
    assert "t_per_cycle=15.0" in msg
    assert "failed_peers=3" in msg
    assert "rerequests=95" in msg
    # Top 3 but not the 4th.
    assert "4.4.4.4:8333=40" in msg
    assert "5.5.5.5:8333=30" in msg
    assert "6.6.6.6:8333=20" in msg
    assert "7.7.7.7:8333" not in msg


def test_negative_clock_skew_clamped_to_zero(caplog):
    """If connect_time < first_request_time (e.g. NTP adjust) the
    latency contribution must be 0, not a huge positive via unsigned
    wrap or a negative that skews the avg."""
    bs = _make_block_sync()
    bs._w77_first_request_time[b"\x01" * 32] = 10.0
    bs._w77_record_connect(b"\x01" * 32, 5.0)  # 5s backwards
    assert bs._w77_latency_sum_s == 0.0
    assert bs._w77_latency_max_s == 0.0
