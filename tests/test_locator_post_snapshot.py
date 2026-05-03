"""Unit tests for ``BlockSync._build_locator`` post-snapshot regression.

Background: after a ``loadtxoutset`` recovery, ``BLOCK_INDEX_CF``
(height -> hash mapping) is empty for all snapshot-loaded heights.  The
snapshot loader only updates META_CF's ``best_block_hash`` /
``best_height``; the per-height index isn't backfilled until peers
deliver headers (which themselves require a working locator).

The pre-fix locator code walked from ``best_height`` downward via
``db.get_block_hash_by_height(h)`` and silently dropped Nones.  Post
snapshot, every recent height returned None, leaving the locator empty
of the actual tip and full of stale low-height hashes from before the
snapshot.  Peers matched one of those stale hashes and replied with
2000 headers whose ``prev_blockhash`` was the matched stale hash, NOT
our true tip.  ``handle_headers`` rejected every batch with "does not
connect" and the node wedged at h=944183 forever.

Live wedge: 2026-05-02, mainnet ouroboros at h=944183 with the log
spam:

    Header cf247ab093cae5a6... does not connect
        (expected prev 17d8ce98333245ab..., got ebf2a13396772607...)
        — dropping remaining 2000 headers

The fix mirrors Bitcoin Core's ``LocatorEntries`` (chain.cpp:26): the
FIRST entry of every locator is always the chain tip, regardless of
whether the per-height index can serve it.  The tip hash comes from
META_CF via ``db.get_best_block()``, which is always populated.

Reference: bitcoin-core/src/chain.cpp lines 26-43.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ouroboros.block_sync import BlockSync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _h(prefix: bytes, height: int) -> bytes:
    """Stable 32-byte synthetic hash distinguishable across heights."""
    return prefix + height.to_bytes(28, "big")


def _make_block_sync(
    *,
    best_hash: bytes,
    best_height: int,
    height_index: dict[int, bytes] | None = None,
) -> BlockSync:
    """Construct a BlockSync wired up to a mock DB whose
    ``get_block_hash_by_height`` only returns hashes for heights
    explicitly listed in *height_index* (matching the real post-snapshot
    state where BLOCK_INDEX_CF is sparse).
    """
    db = MagicMock()
    db.get_best_block.return_value = (best_hash, best_height)

    def _h_by_height(h: int):
        if height_index is None:
            return None
        return height_index.get(h)

    db.get_block_hash_by_height.side_effect = _h_by_height
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_locator_first_entry_is_tip_post_snapshot():
    """Live mainnet wedge regression.

    Snapshot at 944183 leaves ``BLOCK_INDEX_CF`` empty for that height
    (and every other height >= 1 in this test). The locator MUST still
    include the actual tip hash from META_CF as its first entry, or
    peers will fall back to matching genesis and we'll get headers that
    don't connect.
    """
    tip_hash = _h(b"\xaa\xbb\xcc\xdd", 944183)
    bs = _make_block_sync(
        best_hash=tip_hash,
        best_height=944183,
        # Only genesis is in BLOCK_INDEX_CF — the post-loadtxoutset state.
        height_index={0: _h(b"\x00" * 4, 0)},
    )

    locator = bs._build_locator(944183)

    assert locator, "locator must not be empty after a snapshot recovery"
    assert (
        locator[0] == tip_hash
    ), f"first locator entry must be the tip hash, got {locator[0].hex()[:16]}..."


def test_locator_includes_tip_even_if_height_arg_is_stale():
    """If the caller passes a stale ``height`` (e.g. cached from before
    a chainstate update), the locator should still anchor on the
    authoritative META_CF tip rather than walking from the stale value.
    """
    tip_hash = _h(b"\x11\x22\x33\x44", 944183)
    bs = _make_block_sync(
        best_hash=tip_hash,
        best_height=944183,
        height_index={0: _h(b"\x00" * 4, 0)},
    )

    # Pass an obviously stale height.
    locator = bs._build_locator(0)

    assert locator[0] == tip_hash


def test_locator_sparse_index_does_not_duplicate_tip():
    """When BLOCK_INDEX_CF *does* have an entry for the tip height,
    the tip should still appear exactly once (the META anchor + the
    per-height walk must not double-add it).
    """
    tip_hash = _h(b"\xde\xad\xbe\xef", 944183)
    bs = _make_block_sync(
        best_hash=tip_hash,
        best_height=944183,
        height_index={
            0: _h(b"\x00" * 4, 0),
            944183: tip_hash,  # both META and INDEX agree
            944100: _h(b"\xfe" * 4, 944100),
        },
    )

    locator = bs._build_locator(944183)

    assert locator[0] == tip_hash
    assert locator.count(tip_hash) == 1, (
        "tip hash must appear exactly once in the locator, "
        f"found {locator.count(tip_hash)}"
    )


def test_locator_walks_back_when_index_is_dense():
    """Sanity check: when BLOCK_INDEX_CF is fully populated (the
    no-snapshot case), the locator still has the exponential-spacing
    shape Core's protocol expects.
    """
    height_index = {h: _h(b"\xab" * 4, h) for h in range(0, 100)}
    tip_hash = height_index[99]
    bs = _make_block_sync(
        best_hash=tip_hash,
        best_height=99,
        height_index=height_index,
    )

    locator = bs._build_locator(99)

    # First is tip, last is genesis (or close to it).
    assert locator[0] == tip_hash
    assert height_index[0] in locator
    # No empty entries, all 32 bytes.
    assert all(isinstance(h, (bytes, bytearray)) and len(h) == 32 for h in locator)
    # Reasonable size — Core caps at ~32; ouroboros's exponential walk
    # over 100 heights produces well under that.
    assert 1 < len(locator) <= 32
