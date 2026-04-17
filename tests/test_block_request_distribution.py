"""Unit tests for the per-peer in-flight cap in block request distribution.

Background — wave59-2026-04-17 (OUROBOROS-PEER-IN-FLIGHT-CAP): during
mainnet IBD with ~8 peers and a global cap of 256 in-flight blocks,
round-robin assignment was giving each peer ~32 concurrent requests.
A single slow peer then held 32 blocks hostage for the full 20s timeout
window before re-request, driving sustained re-request storms (log
evidence: 5-20 "block requests timed out" per cycle, same 5 peers
repeatedly flagged).  Bitcoin Core caps per-peer in-flight at
``MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16`` (net_processing.cpp) for exactly
this reason.

These tests exercise the pure-function round-robin helper that both
``_request_next_blocks`` and ``_handle_timeouts`` now route through.
"""

from __future__ import annotations

from ouroboros.block_sync import (
    MAX_BLOCKS_IN_FLIGHT_PER_PEER,
    _distribute_blocks_round_robin,
)


def test_empty_candidates_yields_nothing_assigned():
    per_peer, assigned = _distribute_blocks_round_robin(
        items=[("block", b"\x00" * 32)],
        candidates=[],
        peer_load={},
        max_per_peer=16,
    )
    assert per_peer == {}
    assert assigned == []


def test_even_distribution_under_cap():
    """4 items, 2 peers, cap 16 → 2 per peer, all assigned, peer_load updated."""
    peers = ["A", "B"]
    items = [("block", bytes([i])) for i in range(4)]
    peer_load: dict = {}

    per_peer, assigned = _distribute_blocks_round_robin(
        items, peers, peer_load, max_per_peer=16,
    )

    assert len(assigned) == 4
    assert len(per_peer["A"]) == 2
    assert len(per_peer["B"]) == 2
    assert peer_load == {"A": 2, "B": 2}


def test_cap_bounds_per_peer_assignment():
    """With max_per_peer=3 and a single peer candidate, only 3 items are placed."""
    per_peer, assigned = _distribute_blocks_round_robin(
        items=[("block", bytes([i])) for i in range(10)],
        candidates=["solo"],
        peer_load={},
        max_per_peer=3,
    )
    assert len(assigned) == 3
    assert len(per_peer["solo"]) == 3


def test_existing_load_counts_against_cap():
    """Peer already at cap is skipped even if first in candidate order."""
    peers = ["FULL", "FREE"]
    peer_load = {"FULL": 16, "FREE": 0}

    per_peer, assigned = _distribute_blocks_round_robin(
        items=[("block", bytes([i])) for i in range(5)],
        candidates=peers,
        peer_load=peer_load,
        max_per_peer=16,
    )

    assert len(assigned) == 5
    assert per_peer["FULL"] == []
    assert len(per_peer["FREE"]) == 5
    assert peer_load == {"FULL": 16, "FREE": 5}


def test_items_defer_when_all_peers_at_cap():
    """With every peer at cap, nothing is assigned and items defer to caller."""
    peers = ["A", "B"]
    peer_load = {"A": 16, "B": 16}
    items = [("block", bytes([i])) for i in range(4)]

    per_peer, assigned = _distribute_blocks_round_robin(
        items, peers, peer_load, max_per_peer=16,
    )

    assert assigned == []
    assert per_peer == {"A": [], "B": []}
    # peer_load unchanged
    assert peer_load == {"A": 16, "B": 16}


def test_round_robin_advances_across_calls_within_one_pass():
    """The internal peer_idx advances so a single pass spreads items evenly
    rather than piling the first N onto the first peer up to the cap."""
    peers = ["A", "B", "C"]
    items = [("block", bytes([i])) for i in range(6)]
    peer_load: dict = {}

    per_peer, assigned = _distribute_blocks_round_robin(
        items, peers, peer_load, max_per_peer=16,
    )

    assert len(assigned) == 6
    assert len(per_peer["A"]) == 2
    assert len(per_peer["B"]) == 2
    assert len(per_peer["C"]) == 2


def test_core_matches_mainnet_cap_value():
    """Sanity: we match Bitcoin Core's MAX_BLOCKS_IN_FLIGHT_PER_PEER=16."""
    assert MAX_BLOCKS_IN_FLIGHT_PER_PEER == 16


def test_mainnet_shape_8_peers_256_window_caps_at_128():
    """With 8 peers and a 256-slot global window, the cap reduces maximum
    outstanding to 8*16 = 128, bounding any single peer's hostage to 16."""
    peers = [f"P{i}" for i in range(8)]
    items = [("block", bytes([i, 0])) for i in range(256)]
    peer_load: dict = {}

    per_peer, assigned = _distribute_blocks_round_robin(
        items, peers, peer_load, max_per_peer=MAX_BLOCKS_IN_FLIGHT_PER_PEER,
    )

    assert len(assigned) == 8 * MAX_BLOCKS_IN_FLIGHT_PER_PEER == 128
    for p in peers:
        assert len(per_peer[p]) == MAX_BLOCKS_IN_FLIGHT_PER_PEER
        assert peer_load[p] == MAX_BLOCKS_IN_FLIGHT_PER_PEER
