"""Tests for the assumeUTXO header-metadata backfill (#52).

The defect these guard: a snapshot-bootstrapped node has no block index below
the snapshot base (the live mainnet node's floor was ~948454), so
``get_median_time_past`` cannot compute an MTP for any older height and
``check_sequence_locks`` then treats the coin time as 0 — every BIP-68 relative
TIME lock on a pre-floor coin is silently satisfied.

These tests cover the verification and write logic.  The headers themselves
arrive over P2P, which is the caller's job; keeping this module transport-free
is what makes the trust rules testable without a network.
"""

import pytest

from ouroboros.header_backfill import (
    GENESIS_HASHES,
    BackfillError,
    backfill_metadata,
    block_hash,
    block_work,
    find_index_floor,
    meets_pow,
    missing_mtp_heights,
    parse_header,
    target_from_bits,
    verify_chain,
)

# The real mainnet genesis header, 80 bytes.
MAINNET_GENESIS_HEADER = bytes.fromhex(
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49"
    "ffff001d"
    "1dac2b7c"
)


def make_header(prev_hash: bytes, timestamp: int, bits: int = 0x207FFFFF, nonce: int = 0) -> bytes:
    """Build a synthetic 80-byte header linking to *prev_hash*."""
    return (
        (1).to_bytes(4, "little")
        + prev_hash
        + bytes(32)
        + timestamp.to_bytes(4, "little")
        + bits.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


def make_chain(start_prev: bytes, count: int, first_timestamp: int = 1000):
    """A linked run of *count* synthetic headers."""
    headers, prev = [], start_prev
    for i in range(count):
        h = make_header(prev, first_timestamp + i)
        headers.append(h)
        prev = block_hash(h)
    return headers, prev


class FakeDB:
    """Minimal stand-in exposing only what the backfill touches."""

    def __init__(self, present_heights=()):
        self.heights = {h: bytes([h % 256]) * 32 for h in present_heights}
        self.written = []

    def get_block_hash_by_height(self, height):
        return self.heights.get(height)

    def store_block_metadata_persistent(self, height, hash_, chainwork, timestamp):
        self.written.append((height, hash_, chainwork, timestamp))
        self.heights[height] = hash_


# ---------------------------------------------------------------- primitives

def test_genesis_header_hashes_to_the_known_genesis():
    assert block_hash(MAINNET_GENESIS_HEADER) == GENESIS_HASHES["mainnet"]
    # And in Core's display order.
    assert (
        block_hash(MAINNET_GENESIS_HEADER)[::-1].hex()
        == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )


def test_parse_header_extracts_genesis_fields():
    version, prev, _merkle, timestamp, bits, nonce = parse_header(MAINNET_GENESIS_HEADER)
    assert version == 1
    assert prev == bytes(32)
    assert timestamp == 1231006505
    assert bits == 0x1D00FFFF
    assert nonce == 2083236893


def test_block_work_matches_core_genesis_chainwork():
    # Core reports the genesis block's chainwork as 0x0000...0100010001.
    assert block_work(0x1D00FFFF) == 0x100010001


def test_target_from_bits_and_zero_mantissa():
    assert target_from_bits(0x1D00FFFF) == 0xFFFF << (8 * (0x1D - 3))
    assert target_from_bits(0x1D000000) == 0
    assert block_work(0x1D000000) == 0


def test_meets_pow_accepts_genesis_and_rejects_a_tampered_header():
    assert meets_pow(MAINNET_GENESIS_HEADER)
    # Bump the nonce: the hash no longer clears the difficulty-1 target.
    tampered = MAINNET_GENESIS_HEADER[:76] + (12345).to_bytes(4, "little")
    assert not meets_pow(tampered)


def test_header_size_is_enforced():
    with pytest.raises(BackfillError):
        block_hash(b"\x00" * 79)
    with pytest.raises(BackfillError):
        parse_header(b"\x00" * 81)


# ------------------------------------------------------------- floor finding

def test_find_index_floor_returns_zero_when_index_reaches_genesis():
    assert find_index_floor(FakeDB(present_heights=range(0, 100)), 99) == 0


def test_find_index_floor_locates_a_snapshot_base():
    # Mirrors the live mainnet shape: nothing below 948454.
    db = FakeDB(present_heights=range(948454, 964040))
    assert find_index_floor(db, 964039) == 948454


def test_find_index_floor_rejects_an_absent_tip():
    # Genesis must be absent for this to be reachable: when height 0 IS
    # present the floor is 0 and there is nothing to backfill, whatever the
    # tip looks like, so that case short-circuits by design.
    with pytest.raises(BackfillError, match="not contiguous"):
        find_index_floor(FakeDB(present_heights=range(100, 200)), 500)


def test_find_index_floor_short_circuits_on_genesis_regardless_of_tip():
    # Genesis present => floor 0 => nothing to backfill, no contiguity probe.
    assert find_index_floor(FakeDB(present_heights=range(0, 10)), 500) == 0


# -------------------------------------------------------------- verification

def test_verify_chain_accepts_a_linked_range_that_reaches_the_anchor():
    headers, anchor = make_chain(bytes(32), 5)
    verify_chain(headers, start_height=10, anchor_hash=anchor, check_pow=False)


def test_verify_chain_rejects_a_broken_link():
    headers, anchor = make_chain(bytes(32), 5)
    # Repoint header 3 at nothing.
    headers[3] = make_header(b"\xee" * 32, 1003)
    with pytest.raises(BackfillError, match="does not link"):
        verify_chain(headers, start_height=10, anchor_hash=anchor, check_pow=False)


def test_verify_chain_rejects_a_range_that_misses_the_anchor():
    # THE load-bearing check: a self-consistent chain that simply is not ours.
    headers, _ = make_chain(bytes(32), 5)
    with pytest.raises(BackfillError, match="does not reach the anchor"):
        verify_chain(headers, start_height=10, anchor_hash=b"\xab" * 32, check_pow=False)


def test_verify_chain_rejects_a_wrong_genesis_at_height_zero():
    headers, anchor = make_chain(bytes(32), 3)
    with pytest.raises(BackfillError, match="genesis mismatch"):
        verify_chain(headers, start_height=0, anchor_hash=anchor, check_pow=False)


def test_verify_chain_accepts_the_real_genesis_at_height_zero():
    tail, anchor = make_chain(block_hash(MAINNET_GENESIS_HEADER), 3)
    verify_chain(
        [MAINNET_GENESIS_HEADER] + tail,
        start_height=0,
        anchor_hash=anchor,
        check_pow=False,
    )


def test_verify_chain_rejects_headers_failing_their_own_pow():
    headers, anchor = make_chain(bytes(32), 3)
    # bits=0x1d00ffff demands real work these synthetic headers do not have.
    headers = [h[:72] + (0x1D00FFFF).to_bytes(4, "little") + h[76:] for h in headers]
    relinked, prev = [], bytes(32)
    for h in headers:
        h = h[:4] + prev + h[36:]
        relinked.append(h)
        prev = block_hash(h)
    with pytest.raises(BackfillError, match="does not meet its own target"):
        verify_chain(relinked, start_height=10, anchor_hash=prev, check_pow=True)


def test_verify_chain_rejects_an_empty_range():
    with pytest.raises(BackfillError, match="empty header range"):
        verify_chain([], start_height=0, anchor_hash=bytes(32))


# --------------------------------------------------------------- persistence

def test_backfill_writes_one_row_per_height_with_cumulative_chainwork():
    headers, anchor = make_chain(bytes(32), 4, first_timestamp=500)
    db = FakeDB()
    written = backfill_metadata(
        db, headers, start_height=7, anchor_hash=anchor, check_pow=False
    )
    assert written == 4
    assert [row[0] for row in db.written] == [7, 8, 9, 10]
    assert [row[3] for row in db.written] == [500, 501, 502, 503]
    # Chainwork accumulates, never resets.
    works = [row[2] for row in db.written]
    assert works == sorted(works)
    assert len(set(works)) == 4
    unit = block_work(0x207FFFFF)
    assert works == [unit, unit * 2, unit * 3, unit * 4]


def test_backfill_honours_a_base_chainwork():
    headers, anchor = make_chain(bytes(32), 2)
    db = FakeDB()
    backfill_metadata(
        db, headers, start_height=1, anchor_hash=anchor,
        base_chainwork=1000, check_pow=False,
    )
    unit = block_work(0x207FFFFF)
    assert [row[2] for row in db.written] == [1000 + unit, 1000 + 2 * unit]


def test_a_rejected_range_writes_nothing():
    """Verification runs to completion before the first write.

    Without this a lying peer could leave a partially-poisoned index behind.
    """
    headers, anchor = make_chain(bytes(32), 5)
    headers[4] = make_header(b"\xee" * 32, 9999)
    db = FakeDB()
    with pytest.raises(BackfillError):
        backfill_metadata(db, headers, start_height=1, anchor_hash=anchor, check_pow=False)
    assert db.written == []


# ---------------------------------------------------------------- diagnostic

def test_missing_mtp_heights_reports_the_pre_floor_gap():
    """The BIP-68 question stated directly: is this height evaluable?"""
    db = FakeDB(present_heights=range(948454, 964040))
    # A coin confirmed long before the snapshot base — its window is absent.
    assert missing_mtp_heights(db, [500000]) == [500000]
    # Straddling the floor: the window dips below it, so still not computable.
    assert missing_mtp_heights(db, [948460]) == [948460]
    # Clear of the floor by a full window: computable.
    assert missing_mtp_heights(db, [948464]) == []


def test_missing_mtp_heights_is_empty_once_backfilled():
    db = FakeDB(present_heights=range(948454, 964040))
    assert missing_mtp_heights(db, [500000]) == [500000]
    for h in range(499990, 948454):
        db.heights[h] = bytes(32)
    assert missing_mtp_heights(db, [500000]) == []


# ------------------------------- database.py get_block_hash_by_height fallback

class RaisingDB:
    """Rust layer that raises, forcing the Python fallback path."""

    def __init__(self, block=None):
        self._block = block

    def get_block_hash_by_height(self, height):
        raise RuntimeError("rust layer unavailable")


def test_get_block_hash_by_height_fallback_returns_none_for_a_missing_block():
    """The fallback must return None, not raise UnboundLocalError.

    `h` was bound only inside `if block:`, so a falsy block reached
    `if h is None` with `h` unbound — turning "not found" into a crash on the
    one path whose whole job is to handle "not found".
    """
    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase.__new__(BlockchainDatabase)
    db._db = RaisingDB()
    db.get_block_by_height = lambda height: None

    assert db.get_block_hash_by_height(123) is None


# ------------------------------------------------------------------- driver

from ouroboros.header_backfill import HeaderBackfill  # noqa: E402


def _genesis_chain(count: int):
    """Real mainnet genesis followed by `count` synthetic linked headers."""
    tail, anchor = make_chain(block_hash(MAINNET_GENESIS_HEADER), count)
    return [MAINNET_GENESIS_HEADER] + tail, anchor


class TestHeaderBackfillDriver:
    def test_start_locator_is_genesis_then_resumes_from_the_buffer(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        assert bf.start_locator() == [GENESIS_HASHES["mainnet"]]
        bf.accept(headers[:2])
        # Re-request resumes rather than restarting the whole walk.
        assert bf.start_locator() == [block_hash(headers[1])]

    def test_accept_buffers_in_order_and_completes_at_the_floor(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        assert bf.accept(headers[:2]) == 2
        assert not bf.is_complete()
        assert bf.progress() == (2, 4)
        bf.accept(headers[2:])
        assert bf.is_complete()
        assert bf.next_height == 4

    def test_first_header_must_be_genesis(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        with pytest.raises(BackfillError, match="not mainnet genesis"):
            bf.accept(headers[1:])

    def test_a_batch_that_does_not_link_is_rejected(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers[:2])
        with pytest.raises(BackfillError, match="does not link"):
            bf.accept([make_header(b"\xee" * 32, 7777)])

    def test_commit_refuses_while_incomplete(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers[:2])
        db = FakeDB()
        with pytest.raises(BackfillError, match="incomplete backfill"):
            bf.commit(db, check_pow=False)
        assert db.written == []

    def test_commit_writes_every_height_and_releases_the_buffer(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers)
        db = FakeDB()
        assert bf.commit(db, check_pow=False) == 4
        assert [row[0] for row in db.written] == [0, 1, 2, 3]
        assert bf.committed
        assert bf.headers == []  # ~76 MB released at mainnet scale

    def test_commit_with_a_wrong_anchor_writes_nothing(self):
        """A peer that serves a self-consistent chain that is not ours."""
        headers, _ = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=b"\xab" * 32)
        bf.accept(headers)
        db = FakeDB()
        with pytest.raises(BackfillError, match="does not reach the anchor"):
            bf.commit(db, check_pow=False)
        assert db.written == []
        assert not bf.committed

    def test_double_commit_is_refused(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers)
        db = FakeDB()
        bf.commit(db, check_pow=False)
        with pytest.raises(BackfillError, match="already committed"):
            bf.commit(db, check_pow=False)

    def test_driver_requires_a_real_floor(self):
        with pytest.raises(BackfillError, match="must be > 0"):
            HeaderBackfill(floor_height=0, anchor_hash=bytes(32))


class TestHeaderBackfillRouting:
    """`wants()` must not steal ordinary sync batches, or be stolen from."""

    def test_wants_genesis_batch_when_empty(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        assert bf.wants(headers)

    def test_does_not_want_an_unrelated_batch(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        unrelated, _ = make_chain(b"\x77" * 32, 2)
        assert not bf.wants(unrelated)

    def test_wants_the_continuation_after_a_partial_batch(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers[:2])
        assert bf.wants(headers[2:])
        assert not bf.wants(headers[:1])  # already-held prefix

    def test_wants_is_false_once_complete_or_committed(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        bf.accept(headers)
        assert not bf.wants(headers)     # complete
        bf.commit(FakeDB(), check_pow=False)
        assert not bf.wants(headers)     # committed

    def test_wants_is_non_mutating(self):
        headers, anchor = _genesis_chain(3)
        bf = HeaderBackfill(floor_height=4, anchor_hash=anchor)
        before = bf.next_height
        bf.wants(headers)
        assert bf.next_height == before
