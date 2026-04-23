"""Unit tests for plan-W97 `_find_next_blocks_per_peer`.

The per-peer scheduler is the Bitcoin Core
`FindNextBlocksToDownload` analog that replaces the pre-W97 round-robin
path in `_request_next_blocks`.  These tests pin the contract:

- Contiguous assignment (peer A gets the head-of-window chunk, peer B
  gets the next chunk, …) rather than interleaved round-robin.
- Capacity-based — respects `max_per_peer - peer_load[peer]`.
- Window-bounded — never walks past `tip_idx + window`.
- Skips blocks already in `requested_blocks` (in flight elsewhere).
- Skips blocks already on disk (plan-W96 pending store, or the legacy
  in-memory buffer under the flag-off compatibility path).
- No double-assignment across peers in the same pass.
- Honors peer ordering — caller sorts before calling (W92 score-sort).
- `peer_load` is mutated in place so chained passes reflect progress.
"""

from __future__ import annotations

from ouroboros.block_sync import _find_next_blocks_per_peer


def _hdr(seed: int) -> tuple[bytes, object]:
    """Fake (hash, header) pair.  Header isn't inspected — only the hash."""
    return (seed.to_bytes(32, "big"), None)


def _chain(n: int) -> list:
    return [_hdr(i) for i in range(n)]


def test_no_peers_returns_empty():
    got = _find_next_blocks_per_peer(
        validated_headers=_chain(10),
        tip_idx=-1,
        window=1024,
        peers=[],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert got == {}


def test_no_headers_returns_empty_map_for_each_peer():
    peer_a = object()
    got = _find_next_blocks_per_peer(
        validated_headers=[],
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert got == {peer_a: []}


def test_single_peer_gets_contiguous_head_of_window():
    peer_a = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    expected = [chain[i][0] for i in range(16)]
    assert got[peer_a] == expected


def test_capacity_respects_existing_peer_load():
    """If peer already has 10 in flight (cap 16), they get only 6 more."""
    peer_a = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={peer_a: 10},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert len(got[peer_a]) == 6


def test_saturated_peer_gets_nothing():
    peer_a = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={peer_a: 16},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert got[peer_a] == []


def test_two_peers_get_contiguous_disjoint_chunks():
    """Core-style: peer A gets [0..15], peer B gets [16..31].
    Contrast with round-robin which would interleave [0,2,4,…] and
    [1,3,5,…]."""
    peer_a = object()
    peer_b = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a, peer_b],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    a_expected = [chain[i][0] for i in range(16)]
    b_expected = [chain[i][0] for i in range(16, 32)]
    assert got[peer_a] == a_expected
    assert got[peer_b] == b_expected


def test_head_of_window_goes_to_first_peer_in_list():
    """Caller controls head-of-window via peer ordering (W92 score-sort)."""
    fast = object()
    slow = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[fast, slow],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert got[fast][0] == chain[0][0]
    assert got[slow][0] == chain[16][0]


def test_skips_already_requested_blocks():
    """Block already in flight elsewhere must not be re-assigned."""
    peer_a = object()
    chain = _chain(100)
    # Block at index 0 already requested from a previous scheduling pass.
    requested = {chain[0][0]}
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=requested,
    )
    # Peer gets 16 blocks starting at index 1 (0 was skipped).
    expected = [chain[i][0] for i in range(1, 17)]
    assert got[peer_a] == expected


def test_skips_blocks_already_on_disk():
    """plan-W96 disk buffer: already-received blocks (awaiting drain)
    must not be re-requested."""
    peer_a = object()
    chain = _chain(100)
    # Blocks at indices 0, 2 have arrived and sit in the pending store.
    on_disk_hashes = {chain[0][0], chain[2][0]}
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
        is_on_disk=on_disk_hashes.__contains__,
    )
    # 16 blocks, skipping indices 0 and 2: [1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]
    expected_indices = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    assert got[peer_a] == [chain[i][0] for i in expected_indices]


def test_no_double_assignment_across_peers():
    """With capacity > available-blocks, the second peer must still not
    receive the same blocks the first peer got."""
    peer_a = object()
    peer_b = object()
    chain = _chain(10)  # only 10 blocks
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a, peer_b],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    a_hashes = set(got[peer_a])
    b_hashes = set(got[peer_b])
    assert a_hashes & b_hashes == set()
    assert len(a_hashes) + len(b_hashes) == 10


def test_window_bounds_lookahead():
    """Walk must stop at tip_idx + window even if peers have capacity."""
    peer_a = object()
    chain = _chain(100)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=5,  # tiny window
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,  # capacity 16 > window 5
        requested_blocks=set(),
    )
    # Peer has capacity 16 but window only grants 5 blocks.
    assert len(got[peer_a]) == 5
    assert got[peer_a] == [chain[i][0] for i in range(5)]


def test_tip_idx_controls_walk_start():
    """Header-chain offset: walk starts at tip_idx + 1."""
    peer_a = object()
    chain = _chain(100)
    # tip_idx=4 means blocks [0..4] are already connected; walk from 5.
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=4,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    expected = [chain[i][0] for i in range(5, 21)]
    assert got[peer_a] == expected


def test_peer_load_is_mutated_in_place():
    """Contract-parity with `_distribute_blocks_round_robin`: callers can
    chain additional assignment passes against the returned peer_load."""
    peer_a = object()
    chain = _chain(100)
    peer_load = {peer_a: 2}
    _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load=peer_load,
        max_per_peer=16,
        requested_blocks=set(),
    )
    # Started at 2, assigned 14 more, should end at 16.
    assert peer_load[peer_a] == 16


def test_empty_window_after_start_returns_empty_lists():
    """tip_idx is past the last header — nothing to assign."""
    peer_a = object()
    chain = _chain(10)
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=10,  # past end
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert got[peer_a] == []


def test_dict_requested_blocks_accepted():
    """Real call site passes `self.requested_blocks: dict[hash, float]`,
    not a set.  Both must work (Container[bytes] protocol)."""
    peer_a = object()
    chain = _chain(100)
    requested = {chain[0][0]: 123.0}  # dict
    got = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[peer_a],
        peer_load={},
        max_per_peer=16,
        requested_blocks=requested,
    )
    # Same as set version — block 0 skipped, peer gets [1..16].
    assert got[peer_a][0] == chain[1][0]
    assert len(got[peer_a]) == 16


def test_fast_peer_gets_more_blocks_over_multiple_passes():
    """Simulates steady-state IBD: fast peer clears its in-flight slots
    faster, so the next scheduling pass gives them more of the head-of-
    window.  This is the W97 "capacity-based scheduling" property."""
    fast = object()
    slow = object()

    # Pass 1 — both peers idle.
    chain = _chain(100)
    peer_load = {fast: 0, slow: 0}
    pass1 = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[fast, slow],
        peer_load=peer_load,
        max_per_peer=16,
        requested_blocks=set(),
    )
    assert len(pass1[fast]) == 16
    assert len(pass1[slow]) == 16
    requested = {h: 0.0 for h in pass1[fast] + pass1[slow]}

    # Fast peer delivers 10 blocks while slow peer delivers 0.
    # Simulate that by removing 10 from `requested` and decrementing
    # fast's load by 10.
    for h in pass1[fast][:10]:
        del requested[h]
    peer_load[fast] -= 10

    # Pass 2 — fast peer has 6 in flight, slow has 16; window advanced.
    pass2 = _find_next_blocks_per_peer(
        validated_headers=chain,
        tip_idx=-1,
        window=1024,
        peers=[fast, slow],
        peer_load=peer_load,
        max_per_peer=16,
        requested_blocks=requested,
    )
    # Fast gets 10 fresh assignments (to refill to cap); slow gets 0.
    assert len(pass2[fast]) == 10
    assert len(pass2[slow]) == 0
