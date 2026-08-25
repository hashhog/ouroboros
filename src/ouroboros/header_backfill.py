"""Backfill per-height block metadata below an assumeUTXO snapshot base.

WHY THIS EXISTS
---------------
A node bootstrapped from an assumeUTXO snapshot has no block index below the
snapshot base.  On mainnet the live node's index floor was ~948454:
``getblockhash`` returned "Block not found" for heights 100000, 500000 and
900000 while answering normally at 948454 and above.

That is a consensus defect, not a cosmetic gap.  BIP-68 relative *time* locks
are evaluated against the median-time-past of the block that confirmed the
SPENT COIN (Core ``CalculateSequenceLocks``, tx_verify.cpp:74).  Ouroboros's
``get_median_time_past`` correctly refuses to median a partial 11-block window
— a truncated window skews toward recent, larger timestamps and produced an
MTP up to ~2200s too large, which rejected valid blocks and wedged IBD at
h=948464 on 2026-05-20.  Refusing returns ``None``, and ``check_sequence_locks``
then treats the coin time as 0, so the relative time-lock passes.

The consequence is NOT confined to the snapshot boundary: any coin confirmed
below the floor has no computable MTP, so its relative time-lock is skipped
permanently, at any tip height.  Most of the UTXO set is older than the base.

Neither cheap option is correct:
  * fail open (the current behaviour) accepts blocks Core rejects;
  * fail closed rejects blocks Core accepts, i.e. the May 2026 wedge.
Only real history resolves it.  Bitcoin Core validates the FULL header chain
from genesis before loading a snapshot precisely so this question is always
answerable.

WHAT MTP ACTUALLY NEEDS
-----------------------
``get_median_time_past`` (ferrous-utils ``lib.rs`` ``get_median_time_past``)
reads ``get_block_metadata(h).timestamp`` for each height in the window; full
block deserialization is only a fallback when metadata is missing.  So the
backfill needs per-height *metadata* — a hash, a cumulative chainwork and a
timestamp — and NOT block bodies.  ``store_block_metadata_persistent``
(database.py) writes exactly that, through to both the height-keyed
``BLOCK_INDEX_CF`` and the hash-keyed ``BLOCK_INDEX_BY_HASH_CF``.

Note that ``store_raw_header_with_chainwork`` is NOT the right writer: it
touches ``HEADERS_CF`` only, which ``get_median_time_past`` never reads.

TRUST MODEL
-----------
Headers arrive from peers, so they are untrusted input.  ``verify_chain``
enforces three properties before a single row is written:

1. **Genesis anchor** — header 0 must hash to the network's genesis hash.
2. **Linkage** — every header's ``prev_block_hash`` must equal the previous
   header's hash.
3. **Anchor** — the last header must hash to the block already known at the
   floor height.

Together these mean a caller cannot be fed a substituted chain: the range is
pinned at BOTH ends by hashes we already trust, and linked hash-by-hash in
between.  Proof-of-work is additionally checked per header so a peer cannot
cheaply grind an alternative that satisfies the endpoints.

This module is deliberately transport-free: it takes an iterable of raw 80-byte
headers.  Fetching them over P2P is the caller's job, which keeps the
verification logic unit-testable without a network.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

HEADER_SIZE = 80

# Mainnet/testnet/regtest genesis block hashes, internal (little-endian) byte
# order — the order ``block_hash`` below returns and the order the database
# stores.  Display hex is the reverse of these.
GENESIS_HASHES: dict[str, bytes] = {
    "mainnet": bytes.fromhex(
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
    ),
    "testnet": bytes.fromhex(
        "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000"
    ),
    "testnet4": bytes.fromhex(
        "43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000"
    ),
    "regtest": bytes.fromhex(
        "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"
    ),
}


class BackfillError(Exception):
    """Raised when a candidate header range fails verification.

    Raised BEFORE any row is written — a rejected range leaves the database
    untouched, so a lying peer cannot poison the index.
    """


def block_hash(header: bytes) -> bytes:
    """Double-SHA256 of an 80-byte header, in internal byte order."""
    if len(header) != HEADER_SIZE:
        raise BackfillError(f"header must be {HEADER_SIZE} bytes, got {len(header)}")
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


def parse_header(header: bytes) -> tuple[int, bytes, bytes, int, int, int]:
    """Return ``(version, prev_hash, merkle_root, timestamp, bits, nonce)``."""
    if len(header) != HEADER_SIZE:
        raise BackfillError(f"header must be {HEADER_SIZE} bytes, got {len(header)}")
    version = int.from_bytes(header[0:4], "little")
    prev_hash = header[4:36]
    merkle_root = header[36:68]
    timestamp = int.from_bytes(header[68:72], "little")
    bits = int.from_bytes(header[72:76], "little")
    nonce = int.from_bytes(header[76:80], "little")
    return version, prev_hash, merkle_root, timestamp, bits, nonce


def target_from_bits(bits: int) -> int:
    """Decode a compact difficulty target (Core ``arith_uint256::SetCompact``)."""
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF
    if mantissa == 0:
        return 0
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def block_work(bits: int) -> int:
    """Work contributed by one header — Core ``GetBlockProof`` (chain.cpp).

    ``2^256 / (target + 1)``.  Mirrors ``node.py::_calculate_block_work``; kept
    here so the backfill has no import dependency on the node object.
    """
    target = target_from_bits(bits)
    if target <= 0:
        return 0
    return (1 << 256) // (target + 1)


def meets_pow(header: bytes) -> bool:
    """True iff the header hashes below its own claimed target."""
    _, _, _, _, bits, _ = parse_header(header)
    target = target_from_bits(bits)
    if target <= 0:
        return False
    # Hash is little-endian internally; compare as a big-endian number the way
    # Core does when it reverses for arith_uint256.
    return int.from_bytes(block_hash(header), "little") <= target


def find_index_floor(db, tip_height: int) -> int:
    """Lowest height present in the block index.

    Returns 0 when the index reaches genesis (nothing to backfill).  Assumes
    the index is contiguous from the floor to the tip, which is what both a
    genesis IBD and a snapshot load produce, so the boundary can be found by
    binary search instead of ~950k probes.
    """
    if tip_height < 0:
        raise BackfillError(f"tip_height must be non-negative, got {tip_height}")
    if db.get_block_hash_by_height(0) is not None:
        return 0

    # Invariant: `missing` is absent, `present` is present, missing < present.
    missing, present = 0, tip_height
    if db.get_block_hash_by_height(present) is None:
        raise BackfillError(
            f"tip height {tip_height} is itself absent from the index — "
            "the index is not contiguous and the floor is undefined"
        )
    while present - missing > 1:
        mid = (missing + present) // 2
        if db.get_block_hash_by_height(mid) is None:
            missing = mid
        else:
            present = mid
    return present


def find_missing_range(
    db, tip_height: int, *, max_probes: int = 400
) -> tuple[int, int] | None:
    """Locate a gap in the block index: ``(first_absent, next_present)``.

    Returns None when the index is contiguous from genesis to the tip.

    This REPLACES the earlier ``find_index_floor``, whose model — "the index is
    empty below some floor" — is simply not what a snapshot-loaded node looks
    like. Measured on the live mainnet node:

        heights 0..107      present
        heights 108..944183 ABSENT      (944,076 heights)
        heights 944184..tip present

    ``find_index_floor`` probes height 0, finds genesis, returns 0, and the
    caller concludes there is nothing to backfill. The backfill shipped inert
    because of exactly that.

    Method: exponential probe upward from 0 for the first absent height, binary
    search to pin it, then binary search up to the tip for the next present
    height. LIMITATION, stated because it is real: the exponential phase can
    step over a gap narrower than its stride at that depth, so this finds a
    LARGE gap reliably (the assumeUTXO case) and may miss a small one. It is a
    detector for the snapshot hole, not a general index-integrity audit.
    """
    if tip_height < 0:
        raise BackfillError(f"tip_height must be non-negative, got {tip_height}")

    probes = 0

    def present(h: int) -> bool:
        nonlocal probes
        probes += 1
        if probes > max_probes:
            raise BackfillError(f"find_missing_range exceeded {max_probes} probes")
        v = db.get_block_hash_by_height(h)
        return isinstance(v, (bytes, bytearray)) and len(v) == 32

    if not present(tip_height):
        raise BackfillError(
            f"tip height {tip_height} is absent from the index — the index is "
            "not usable as a reference"
        )

    if not present(0):
        first_absent = 0
    else:
        lo, step, hi = 0, 1, None
        while lo + step <= tip_height:
            probe_at = lo + step
            if present(probe_at):
                lo = probe_at
                step *= 2
            else:
                hi = probe_at
                break
        if hi is None:
            return None  # contiguous all the way up
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if present(mid):
                lo = mid
            else:
                hi = mid
        first_absent = hi

    lo2, hi2 = first_absent, tip_height  # lo2 absent, hi2 present
    while hi2 - lo2 > 1:
        mid = (lo2 + hi2) // 2
        if present(mid):
            hi2 = mid
        else:
            lo2 = mid
    return (first_absent, hi2)


def verify_chain(
    headers: Sequence[bytes],
    start_height: int,
    anchor_hash: bytes,
    network: str = "mainnet",
    *,
    check_pow: bool = True,
    prev_anchor: bytes | None = None,
) -> None:
    """Validate a contiguous header range before anything is written.

    ``headers[i]`` is the header for ``start_height + i``.  ``anchor_hash`` is
    the hash already known at the height one past the range, i.e. the current
    index floor — the range must link into it.  Raises `BackfillError` on the
    first violation; returns None when the range is sound.
    """
    if not headers:
        raise BackfillError("empty header range")
    if start_height < 0:
        raise BackfillError(f"start_height must be non-negative, got {start_height}")

    if start_height == 0:
        expected_genesis = GENESIS_HASHES.get(network)
        if expected_genesis is None:
            raise BackfillError(f"unknown network {network!r}")
        actual = block_hash(headers[0])
        if actual != expected_genesis:
            raise BackfillError(
                f"genesis mismatch for {network}: header 0 hashes to "
                f"{actual[::-1].hex()}, expected {expected_genesis[::-1].hex()}"
            )
    elif prev_anchor is not None:
        # A range that does not start at genesis is pinned at its LOWER end by
        # the block already known at start_height - 1, exactly as the upper end
        # is pinned by anchor_hash. Both ends must be blocks we already trust,
        # or the range is unanchored and a peer could substitute its own.
        _, first_prev, _, _, _, _ = parse_header(headers[0])
        if first_prev != prev_anchor:
            raise BackfillError(
                f"range does not attach to the block below it at height "
                f"{start_height - 1}: header prev is {first_prev[::-1].hex()}, "
                f"expected {prev_anchor[::-1].hex()}"
            )
    elif start_height > 0:
        raise BackfillError(
            f"a range starting at height {start_height} needs a prev_anchor — "
            "without it the lower end is unpinned"
        )

    prev_hash_of_previous = None
    for offset, header in enumerate(headers):
        height = start_height + offset
        if len(header) != HEADER_SIZE:
            raise BackfillError(
                f"header at height {height} is {len(header)} bytes, "
                f"expected {HEADER_SIZE}"
            )
        if check_pow and not meets_pow(header):
            raise BackfillError(f"header at height {height} does not meet its own target")
        _, prev, _, _, _, _ = parse_header(header)
        if prev_hash_of_previous is not None and prev != prev_hash_of_previous:
            raise BackfillError(
                f"header at height {height} does not link to height {height - 1}: "
                f"prev={prev[::-1].hex()} expected={prev_hash_of_previous[::-1].hex()}"
            )
        prev_hash_of_previous = block_hash(header)

    # The range must terminate at the block we already trust. Without this a
    # peer could serve a self-consistent chain that is simply not ours.
    if prev_hash_of_previous != anchor_hash:
        raise BackfillError(
            f"range does not reach the anchor at height {start_height + len(headers)}: "
            f"last header is {prev_hash_of_previous[::-1].hex()}, "
            f"anchor is {anchor_hash[::-1].hex()}"
        )


def backfill_metadata(
    db,
    headers: Sequence[bytes],
    start_height: int,
    anchor_hash: bytes,
    network: str = "mainnet",
    *,
    base_chainwork: int = 0,
    check_pow: bool = True,
    prev_anchor: bytes | None = None,
) -> int:
    """Verify then persist per-height metadata for ``headers``.

    Writes ``(height, hash, cumulative_chainwork, timestamp)`` for each header
    via ``store_block_metadata_persistent``, which is what
    ``get_median_time_past`` reads back.  Returns the number of rows written.

    Verification runs to completion FIRST, so a bad range writes nothing.
    """
    verify_chain(
        headers, start_height, anchor_hash, network,
        check_pow=check_pow, prev_anchor=prev_anchor,
    )

    chainwork = base_chainwork
    written = 0
    for offset, header in enumerate(headers):
        height = start_height + offset
        _, _, _, timestamp, bits, _ = parse_header(header)
        chainwork += block_work(bits)
        db.store_block_metadata_persistent(
            height, block_hash(header), chainwork, timestamp
        )
        written += 1
    return written


def missing_mtp_heights(db, heights: Iterable[int]) -> list[int]:
    """Heights whose 11-block MTP window cannot currently be computed.

    A diagnostic for operators and tests: it answers "would a BIP-68 relative
    time lock on a coin at this height be evaluated, or silently skipped?"
    """
    out = []
    for height in heights:
        start = max(0, height - 10)
        if any(db.get_block_hash_by_height(h) is None for h in range(start, height + 1)):
            out.append(height)
    return out


class HeaderBackfill:
    """Drives a header walk over ONE gap in the block index and commits it whole.

    Lifecycle, deliberately all-or-nothing:

      1. ``start_locator()`` — the caller sends a getheaders with this locator,
         so the peer replies from ``start_height`` forward.
      2. ``accept(headers)`` — feed batches in order. They are buffered and
         linkage-checked incrementally so a lying peer is dropped early, but
         NOTHING is written yet.
      3. ``is_complete()`` becomes true once the buffer spans the gap.
      4. ``commit(db)`` — re-verifies the WHOLE range (lower anchor or genesis,
         full linkage, upper anchor, per-header PoW) and only then writes.

    Buffering the entire range before writing is the point. ``verify_chain``
    pins the range at BOTH ends; a chunk-at-a-time writer could only pin the
    near end, so a peer that fed a good prefix and then diverged would leave
    committed rows behind. At mainnet scale the buffer is ~944k * 80 B =
    ~76 MB, paid once for a range that is then permanent, and released on
    commit.

    The range is ``[start_height, end_height)``. ``anchor_hash`` is the block
    already known AT ``end_height`` (the upper pin); ``prev_anchor`` is the
    block already known at ``start_height - 1`` (the lower pin), and is
    required unless the range starts at genesis.

    Transport-free — the caller owns getheaders and message routing — so the
    state machine is unit-testable without a network.
    """

    def __init__(
        self,
        start_height: int,
        end_height: int,
        anchor_hash: bytes,
        prev_anchor: bytes | None = None,
        network: str = "mainnet",
    ):
        if start_height < 0:
            raise BackfillError(f"start_height must be >= 0, got {start_height}")
        if end_height <= start_height:
            raise BackfillError(
                f"empty range: end_height {end_height} <= start_height {start_height}"
            )
        if len(anchor_hash) != 32:
            raise BackfillError("anchor_hash must be 32 bytes")
        if start_height > 0 and (prev_anchor is None or len(prev_anchor) != 32):
            raise BackfillError(
                f"a range starting at height {start_height} needs a 32-byte "
                "prev_anchor — without it the lower end is unpinned"
            )
        self.start_height = start_height
        self.end_height = end_height
        self.anchor_hash = anchor_hash
        self.prev_anchor = prev_anchor
        self.network = network
        self.headers: list[bytes] = []
        self.committed = False

    @property
    def target(self) -> int:
        """How many headers span the gap."""
        return self.end_height - self.start_height

    @property
    def next_height(self) -> int:
        """Height the next header would occupy."""
        return self.start_height + len(self.headers)

    def _expected_prev(self) -> bytes | None:
        """Hash the next header's ``prev`` must equal, or None at genesis."""
        if self.headers:
            return block_hash(self.headers[-1])
        if self.start_height == 0:
            return None
        return self.prev_anchor

    def start_locator(self) -> list[bytes]:
        """Locator for the getheaders that advances the walk.

        A locator names blocks we HAVE; the peer replies with their successors.
        So the entry is the block below the next height we need — which makes a
        re-request resume rather than restart.
        """
        if self.headers:
            return [block_hash(self.headers[-1])]
        if self.start_height == 0:
            expected_genesis = GENESIS_HASHES.get(self.network)
            if expected_genesis is None:
                raise BackfillError(f"unknown network {self.network!r}")
            return [expected_genesis]
        return [self.prev_anchor]

    def wants(self, headers: Sequence[bytes]) -> bool:
        """True iff this batch continues the walk — non-mutating.

        The caller needs this to decide ROUTING before committing to a batch:
        ``accept`` raises on a mismatch, which is right for a backfill batch and
        wrong for an ordinary sync batch that merely arrives while a backfill is
        in flight. Checking first keeps the two paths from stealing each other's
        headers.
        """
        if self.committed or self.is_complete() or not headers:
            return False
        first = headers[0]
        if len(first) != HEADER_SIZE:
            return False
        expected_prev = self._expected_prev()
        if expected_prev is None:
            return block_hash(first) == GENESIS_HASHES.get(self.network)
        _, prev, _, _, _, _ = parse_header(first)
        return prev == expected_prev

    def accept(self, headers: Sequence[bytes]) -> int:
        """Buffer a batch, checking linkage as it arrives. Returns how many were taken.

        A header that does not link is a hard error: the peer is not serving our
        chain and continuing would waste the walk. Nothing reaches the database
        from here.
        """
        if self.committed:
            raise BackfillError("backfill already committed")
        taken = 0
        for header in headers:
            if len(header) != HEADER_SIZE:
                raise BackfillError(
                    f"header at height {self.next_height} is {len(header)} bytes"
                )
            if self.is_complete():
                break
            expected_prev = self._expected_prev()
            if expected_prev is None:
                expected = GENESIS_HASHES.get(self.network)
                if expected is None:
                    raise BackfillError(f"unknown network {self.network!r}")
                if block_hash(header) != expected:
                    raise BackfillError(
                        f"first backfill header is not {self.network} genesis: "
                        f"{block_hash(header)[::-1].hex()}"
                    )
            else:
                _, prev, _, _, _, _ = parse_header(header)
                if prev != expected_prev:
                    raise BackfillError(
                        f"header at height {self.next_height} does not link to "
                        f"the buffered chain"
                    )
            self.headers.append(header)
            taken += 1
        return taken

    def is_complete(self) -> bool:
        """True once the buffer spans ``[start_height, end_height)``.

        The header AT ``end_height`` is already in the index — it is the anchor
        the range must link into, not something to re-fetch.
        """
        return len(self.headers) >= self.target

    def progress(self) -> tuple[int, int]:
        """``(buffered, target)`` for logging."""
        return len(self.headers), self.target

    def commit(self, db, *, check_pow: bool = True, base_chainwork: int = 0) -> int:
        """Verify the whole range, then write it. Returns rows written."""
        if self.committed:
            raise BackfillError("backfill already committed")
        if not self.is_complete():
            raise BackfillError(
                f"refusing to commit an incomplete backfill "
                f"({len(self.headers)}/{self.target})"
            )
        written = backfill_metadata(
            db,
            self.headers,
            start_height=self.start_height,
            anchor_hash=self.anchor_hash,
            network=self.network,
            check_pow=check_pow,
            prev_anchor=self.prev_anchor,
            base_chainwork=base_chainwork,
        )
        self.committed = True
        self.headers = []  # release ~76 MB at mainnet scale
        return written
