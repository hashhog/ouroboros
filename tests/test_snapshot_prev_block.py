"""Regression tests for the post-snapshot prev-block lookup wedge.

Background: when ``loadtxoutset`` finishes, only ``META_CF`` (best block
hash + height) is updated.  ``BLOCKS_CF`` is left empty for the snapshot
tip because the snapshot wire format does not carry block bytes -- only
the UTXO set + the ``base_blockhash`` reference.

The downstream effect: when block N+1 (the FIRST block above the
snapshot tip) arrives, ``BlockValidator.validate_block`` calls
``self.db.get_block(block.prev_blockhash)`` looking for the snapshot
tip's bytes, gets ``None``, and returns ``"Previous block not found"``.
The block_sync drain loop re-buffers the block, which never makes
progress and the node wedges forever at the snapshot height.

Live wedge: 2026-05-02, mainnet ouroboros at h=944183 -- header sync
worked, every block at h=944184 failed with "Previous block not found",
loop forever.

The fix mirrors Bitcoin Core's ``LookupBlockIndex(snap_hash)``: Core
returns the in-memory ``CBlockIndex`` for the snapshot tip (populated
by header sync that runs before snapshot load), and the prev-link
header check uses that lightweight metadata -- the full prev block
bytes are NOT required.

In ouroboros, headers aren't separately persisted, so we bake the
80-byte block header into ``AssumeutxoData.base_header`` for known
snapshot heights and write it alongside ``base_blockhash`` at snapshot
load time.  ``BlockValidator._synthesize_snapshot_prev_block`` reads
the header back and constructs a synthetic ``Block`` (empty txdata)
that satisfies the prev-block accesses in ``validate_block`` --
specifically ``timestamp``, ``bits``, ``height``, and the
``prev_blockhash`` link.

References:
- bitcoin-core/src/validation.cpp Chainstate::SnapshotBase()
  (m_chainman.m_blockman.LookupBlockIndex(*m_from_snapshot_blockhash))
- bitcoin-core/src/node/blockstorage.cpp LookupBlockIndex (cheap,
  hash -> CBlockIndex*) vs ReadBlockFromDisk (expensive, fetches bytes)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from ouroboros.database import Block
from ouroboros.snapshot import (
    SnapshotManager,
    _MAINNET_ASSUMEUTXO,
    get_assumeutxo_data,
)
from ouroboros.validation import BlockValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _MinimalDB:
    """Minimal stub with the methods BlockValidator hits.

    ``get_block`` always returns None (post-snapshot state).  Other
    methods serve plausible defaults so the validator can advance
    past the prev-block check into the rest of the validation logic.
    """

    best_hash: bytes
    best_height: int

    def get_block(self, _hash: bytes):
        return None

    def get_best_block(self) -> tuple[bytes, int]:
        return self.best_hash, self.best_height

    def get_median_time_past(self, _height: int):
        # Returning 0 disables the MTP check in _validate_header --
        # mirrors the "no recent block timestamps available" boundary
        # case that exists naturally right after a snapshot load.
        return 0

    def get_block_by_height(self, _height: int):
        return None

    def get_utxo(self, _txid: bytes, _vout: int):
        return None


def _hash80(header: bytes) -> bytes:
    """SHA256d the 80-byte header to get the block hash (internal byte order)."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


# ---------------------------------------------------------------------------
# AssumeutxoData base_header byte-vs-hash verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("au", _MAINNET_ASSUMEUTXO, ids=lambda au: f"h={au.height}")
def test_mainnet_base_header_round_trips(au) -> None:
    """Every hardcoded mainnet ``base_header`` must SHA256d to its
    declared ``block_hash``.  Catches typos in the chainparams table.
    """
    assert au.base_header is not None, (
        f"mainnet snapshot at h={au.height} is missing base_header; the "
        f"post-snapshot prev-block fallback will not work for this height"
    )
    assert len(au.base_header) == 80
    assert _hash80(au.base_header) == au.block_hash, (
        f"base_header for h={au.height} does not hash to declared "
        f"block_hash {au.block_hash[::-1].hex()}"
    )


# ---------------------------------------------------------------------------
# SnapshotManager: read/write base_blockheader sibling file
# ---------------------------------------------------------------------------


def test_write_and_read_snapshot_base_blockheader(tmp_path) -> None:
    """``write_snapshot_base_blockheader`` persists the 80-byte header
    so the validator can read it back on the SAME process or after a
    restart -- the file lives in the snapshot chainstate dir alongside
    ``base_blockhash``.
    """
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.base_header is not None

    sm.write_snapshot_base_blockheader(au.base_header)

    read_back = sm.read_snapshot_base_blockheader()
    assert read_back == au.base_header
    assert _hash80(read_back) == au.block_hash


def test_read_snapshot_base_blockheader_missing(tmp_path) -> None:
    """When the sibling file has not been written (older build, or
    snapshot was loaded from a chainparams entry without ``base_header``),
    the helper must return ``None`` without raising.  Callers depend on
    this for the graceful fallback path.
    """
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    assert sm.read_snapshot_base_blockheader() is None


def test_read_snapshot_base_blockheader_wrong_size(tmp_path) -> None:
    """A short or oversized file (corruption / partial write) must be
    treated as missing rather than fed to the validator -- otherwise
    the synthesized prev block would carry junk timestamp / bits.
    """
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    snap_dir = sm.get_snapshot_chainstate_dir()
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / "base_blockheader").write_bytes(b"\xaa" * 50)
    assert sm.read_snapshot_base_blockheader() is None


# ---------------------------------------------------------------------------
# BlockValidator: synthesize prev block from snapshot header
# ---------------------------------------------------------------------------


def test_synthesize_snapshot_prev_block_returns_block(tmp_path) -> None:
    """When the prev hash matches the snapshot base, the validator
    reconstructs a Block with the timestamp / bits / version / nonce /
    merkle_root / prev_prev fields parsed from the persisted 80-byte
    header.  ``height`` is filled in from the snapshot manager.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.base_header is not None

    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    sm.write_snapshot_base_blockhash(au.block_hash)
    sm.write_snapshot_base_blockheader(au.base_header)
    sm.snapshot_height = au.height
    sm.snapshot_hash = au.block_hash
    sm.snapshot_loaded = True

    db = _MinimalDB(best_hash=au.block_hash, best_height=au.height)
    validator = BlockValidator(db, network="mainnet", snapshot_manager=sm)

    prev = validator._synthesize_snapshot_prev_block(au.block_hash)
    assert prev is not None
    assert prev.hash == au.block_hash
    # Live mainnet h=944183 values (verified against `getblockheader`):
    assert prev.timestamp == 1_775_651_930
    assert prev.bits == 0x17020684
    assert prev.height == 944_183
    # prev_blockhash field of the snapshot tip is its OWN parent
    # (h=944182 = 00000000000000000000d6e603dff7e37cffedb78c4d090436cc428e956a6904).
    expected_prev = bytes.fromhex(
        "00000000000000000000d6e603dff7e37cffedb78c4d090436cc428e956a6904"
    )[::-1]
    assert prev.prev_blockhash == expected_prev


def test_synthesize_snapshot_prev_block_wrong_hash(tmp_path) -> None:
    """If the caller asks for any hash OTHER than the snapshot base,
    the synthesizer returns ``None`` -- it must never claim to know
    a non-snapshot prev block.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    sm.write_snapshot_base_blockhash(au.block_hash)
    sm.write_snapshot_base_blockheader(au.base_header)
    sm.snapshot_height = au.height

    db = _MinimalDB(best_hash=au.block_hash, best_height=au.height)
    validator = BlockValidator(db, network="mainnet", snapshot_manager=sm)

    bogus = bytes(32)
    assert validator._synthesize_snapshot_prev_block(bogus) is None


def test_synthesize_snapshot_prev_block_no_snapshot(tmp_path) -> None:
    """Without a snapshot manager (unit tests, regtest without snapshot
    load), the synthesizer returns ``None`` cleanly -- the validator
    falls through to the original "Previous block not found" path.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    db = _MinimalDB(best_hash=au.block_hash, best_height=au.height)
    validator = BlockValidator(db, network="mainnet", snapshot_manager=None)
    assert validator._synthesize_snapshot_prev_block(au.block_hash) is None


def test_synthesize_snapshot_prev_block_corrupt_header(tmp_path) -> None:
    """If the persisted header doesn't hash back to the recorded base
    blockhash (data corruption, or an attacker-supplied chainparams
    mismatch), the synthesizer rejects it rather than returning a
    poisoned prev block.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    sm.write_snapshot_base_blockhash(au.block_hash)
    # Flip a bit in the header so it no longer hashes to the recorded base.
    bad = bytearray(au.base_header)
    bad[0] ^= 0xFF
    sm.write_snapshot_base_blockheader(bytes(bad))
    sm.snapshot_height = au.height

    db = _MinimalDB(best_hash=au.block_hash, best_height=au.height)
    validator = BlockValidator(db, network="mainnet", snapshot_manager=sm)
    assert validator._synthesize_snapshot_prev_block(au.block_hash) is None


# ---------------------------------------------------------------------------
# End-to-end: validate_block path that previously hit the wedge
# ---------------------------------------------------------------------------


def _make_dummy_child_header(prev_hash: bytes, *, timestamp: int, bits: int) -> Block:
    """Construct a Block whose header alone (no txs) is shaped like the
    block immediately above the snapshot tip.

    PoW will not pass real difficulty, but ``validate_block`` aborts on
    PoW well after the prev-block lookup; we only care that the
    prev-block path no longer rejects with "Previous block not found".
    """
    return Block(
        version=1,
        prev_blockhash=prev_hash,
        merkle_root=bytes(32),
        timestamp=timestamp,
        bits=bits,
        nonce=0,
        transactions=[],
        hash=bytes(32),
    )


def test_validate_block_does_not_return_previous_block_not_found(tmp_path) -> None:
    """The headline wedge regression.  Previously, attempting to
    validate a block whose ``prev_blockhash`` is the snapshot base
    returned ``(False, "Previous block not found")``.  After the fix,
    ``validate_block`` may still reject the block for OTHER reasons
    (e.g. invalid PoW, missing transactions) but it MUST NOT return
    "Previous block not found" -- that exact error is what made the
    block_sync drain loop re-buffer the block forever.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    sm = SnapshotManager(db=None, network="mainnet", data_dir=str(tmp_path))
    sm.write_snapshot_base_blockhash(au.block_hash)
    sm.write_snapshot_base_blockheader(au.base_header)
    sm.snapshot_height = au.height
    sm.snapshot_hash = au.block_hash
    sm.snapshot_loaded = True

    db = _MinimalDB(best_hash=au.block_hash, best_height=au.height)
    validator = BlockValidator(db, network="mainnet", snapshot_manager=sm)

    # Use the same bits as the snapshot tip (non-retarget period; mainnet
    # rule is "block.bits == prev.bits" between retargets) and a plausible
    # forward timestamp.  The block won't fully validate (no real PoW,
    # no coinbase) but the rejection must NOT be "Previous block not found".
    child = _make_dummy_child_header(
        au.block_hash, timestamp=1_775_651_931, bits=0x17020684
    )
    ok, err = validator.validate_block(child, known_height=au.height + 1)
    assert not ok, "synthetic child block must still fail validation overall"
    assert err != "Previous block not found", (
        f"validate_block must NOT short-circuit on prev-block lookup "
        f"after the fix; got: {err!r}"
    )
