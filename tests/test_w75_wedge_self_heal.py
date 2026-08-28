"""The tip-stall watchdog must ACT, not only warn (task #77A, 2026-08-28).

On 2026-08-28 ouroboros sat wedged for 6760s: it held 6 validated headers,
5 buffered blocks and 9 healthy peers, and still could not advance while the
fleet moved on 6 blocks.  Its own watchdog detected this and logged
`[W75-WATCHDOG] tip-stall suspected` every 5 minutes — 22 times — and did
nothing.  Only a process restart cleared it, which located the stuck state in
memory.  The watchdog's own docstring described it as a *diagnostic*, and it
cited a stall doc from April: the class was known for four months and the
response was a warning.

These drive the decision function directly with a synthetic stalled state, so
they pin the behaviour WITHOUT having to reproduce the wedge.
"""
import types

from ouroboros.block_sync import BlockSync


def _stalled_manager():
    """A BlockSync-shaped object carrying only the watchdog's state."""
    m = types.SimpleNamespace()
    m._wedge_recover_after = 900.0
    m._wedge_recover_every = 900.0
    m._last_wedge_recover = 0.0
    m._wedge_recoveries = 0
    m._validated_headers = [object(), object(), object()]
    m._ibd_block_buffer = {b"a": object(), b"b": object()}
    m._ibd_block_buffer_ts = {b"a": 1.0, b"b": 2.0}
    m.requested_blocks = {b"a": 1.0, b"b": 2.0}
    m._block_request_peer = {b"a": object()}
    m._block_source_peer_addr = {b"a": "1.2.3.4:8333"}
    m._w77_first_request_time = {b"a": 1.0}
    return m


def test_persistent_stall_triggers_a_reset():
    m = _stalled_manager()
    fired = BlockSync._maybe_recover_from_wedge(m, 10_000.0, 6760.0, 964399)
    assert fired is True, (
        "a 6760s stall — the exact duration of the 2026-08-28 outage — must "
        "trigger recovery, not just another warning")
    assert not m._validated_headers, "validated-header queue must be dropped"
    assert not m._ibd_block_buffer, "block buffer must be dropped"
    assert not m.requested_blocks, "in-flight request bookkeeping must be dropped"
    assert not m._block_request_peer
    assert not m._block_source_peer_addr
    assert not m._w77_first_request_time, (
        "the telemetry map must be cleared with its siblings or a bulk drop "
        "orphans its entries")
    assert m._wedge_recoveries == 1


def test_short_stall_does_not_reset():
    """A slow-but-progressing sync must never be disturbed."""
    m = _stalled_manager()
    fired = BlockSync._maybe_recover_from_wedge(m, 10_000.0, 400.0, 964399)
    assert fired is False, "400s is past the WARN threshold but below RECOVER"
    assert len(m.requested_blocks) == 2, "in-flight state must be left alone"
    assert m._wedge_recoveries == 0


def test_recovery_is_rate_limited():
    """Back-to-back stalls must not clear state on every watchdog tick."""
    m = _stalled_manager()
    assert BlockSync._maybe_recover_from_wedge(m, 10_000.0, 6760.0, 964399)
    m.requested_blocks = {b"c": 3.0}
    second = BlockSync._maybe_recover_from_wedge(m, 10_100.0, 6860.0, 964399)
    assert second is False, "a second recovery 100s later must be suppressed"
    assert m.requested_blocks == {b"c": 3.0}, "state must survive the suppressed call"
    assert m._wedge_recoveries == 1
