"""Snapshot-booted node: ancestor-dependent consensus values fail CLOSED.

Core validates the full header chain from genesis before it uses an
assumeUTXO snapshot, so CalculateSequenceLocks' coin MTP
(consensus/tx_verify.cpp:74), the BIP113 cutoff / time-too-old prev MTP
(validation.cpp:4092, 4135) and GetNextWorkRequired's period-first ancestor
(pow.cpp:45) are always defined.  A snapshot-booted ouroboros holds no index
rows below the base until the header backfill commits.  These tests pin:

* the lookups RAISE ``MissingAncestorHeaderError`` instead of substituting
  0 / a partial window / the base timestamp / a 4x clamp (each of which the
  pre-fix code did — see the NEGATIVE CONTROL notes);
* with the real header data they return Core's verdict;
* the drain connects nothing until the block index is contiguous.

Real mainnet numbers (Core RPC, 2026-10-03):
  block 932256, prev MTP(932255) = 1768398550
  spends a coin at height 927979 with nSequence 0x004013c7 (time lock,
  5063 * 512 s); Core coin MTP = MTP(927978) = 1765804000 (timestamps
  927968..927978 below).  camlcoin's partial window gave 1765808303 and
  rejected the valid block.
  retarget 931392: first=929376 time 1766634486, prev=931391 time 1767858836
  bits 0x1701e605 -> expected 0x1701ebf2.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

import tests.conftest  # noqa: F401  -- installs the ``sync`` stub

from ouroboros.database import Block, Transaction, TxIn, TxOut
from ouroboros.validation import (
    BlockValidator,
    MissingAncestorHeaderError,
    TransactionValidator,
)

BLOCK_H = 932_256
BLOCK_PREV_MTP = 1_768_398_550
COIN_H = 927_979
SEQ = 0x004013C7
CORE_COIN_MTP = 1_765_804_000
PARTIAL_WINDOW_COIN_MTP = 1_765_808_303  # camlcoin's wrong value
WINDOW_927968_927978 = [
    1765801866, 1765802240, 1765802404, 1765802919, 1765803403, 1765804000,
    1765807568, 1765807695, 1765808303, 1765808711, 1765809159,
]


def _tx() -> Transaction:
    return Transaction(
        txid=b"\xbb" * 32,
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0, script_sig=b"", sequence=SEQ)],
        outputs=[TxOut(value=1, script_pubkey=b"")],
    )


def _tx_validator(coin_mtp):
    db = MagicMock()
    db.get_utxo.return_value = {
        "txid": b"\xaa" * 32, "vout": 0, "value": 100_000,
        "script_pubkey": b"", "height": COIN_H, "is_coinbase": False,
    }

    def _mtp(h):
        assert h == COIN_H - 1, f"coin MTP must be read at coin_height-1, got {h}"
        return coin_mtp

    db.get_median_time_past.side_effect = _mtp
    return TransactionValidator(db, network="mainnet", snapshot_manager=None)


def test_core_window_median_is_core_value():
    assert sorted(WINDOW_927968_927978)[5] == CORE_COIN_MTP


def test_bip68_full_window_accepts_like_core():
    v = _tx_validator(CORE_COIN_MTP)
    assert v.check_sequence_locks(_tx(), BLOCK_H, BLOCK_PREV_MTP) is True


def test_bip68_partial_window_value_would_reject_valid_block():
    # Documents why a partial-window median is never acceptable: it is the
    # camlcoin 932256 false reject.  ouroboros' db refuses to produce it.
    v = _tx_validator(PARTIAL_WINDOW_COIN_MTP)
    assert v.check_sequence_locks(_tx(), BLOCK_H, BLOCK_PREV_MTP) is False


def test_bip68_missing_coin_mtp_fails_closed():
    # NEGATIVE CONTROL: pre-fix this returned True (coin time 0 -> the
    # relative time lock was skipped), i.e. any time-locked spend passed.
    v = _tx_validator(None)
    with pytest.raises(MissingAncestorHeaderError):
        v.check_sequence_locks(_tx(), BLOCK_H, BLOCK_PREV_MTP)


def test_bip68_missing_coin_mtp_fails_closed_even_when_lock_unsatisfied_by_zero():
    # With coin time 0 the pre-fix code accepted a spend Core rejects:
    # one block after the coin, at the coin's own MTP + 1s.
    v = _tx_validator(None)
    with pytest.raises(MissingAncestorHeaderError):
        v.check_sequence_locks(_tx(), COIN_H + 1, CORE_COIN_MTP + 1)


def test_bip68_python_fallback_fails_closed():
    v = _tx_validator(None)
    with pytest.raises(MissingAncestorHeaderError):
        v._check_sequence_locks_py(_tx(), BLOCK_H, BLOCK_PREV_MTP)


def test_bip68_none_is_not_memoised():
    v = _tx_validator(None)
    cache: dict = {}
    with pytest.raises(MissingAncestorHeaderError):
        v.check_sequence_locks(_tx(), BLOCK_H, BLOCK_PREV_MTP, mtp_cache=cache)
    assert cache == {}


# ---------------------------------------------------------------- db layer


def test_db_mtp_refuses_partial_window():
    """``BlockchainDB.get_median_time_past`` returns None (never a partial
    median) when any of the 11 window heights is absent."""
    from ouroboros.database import BlockchainDatabase as BlockchainDB

    db = BlockchainDB.__new__(BlockchainDB)
    present = {927968 + i: t for i, t in enumerate(WINDOW_927968_927978)}
    del present[927968]  # lowest header below the band
    inner = MagicMock()
    inner.get_median_time_past.return_value = sorted(present.values())[5]
    inner.get_block_hash_by_height.side_effect = (
        lambda h: (b"\x01" * 32) if h in present else None
    )
    db._db = inner
    assert db.get_median_time_past(927978) is None


# ---------------------------------------------------------- validate_block


def _child_block(prev_hash: bytes, ts: int) -> Block:
    return Block(
        version=0x20000000, prev_blockhash=prev_hash, merkle_root=b"\x00" * 32,
        timestamp=ts, bits=0x1701EBF2, nonce=0, transactions=[],
        hash=b"\x02" * 32, height=None,
    )


def test_validate_block_missing_prev_mtp_fails_closed():
    # NEGATIVE CONTROL: pre-fix the window miss was replaced by the snapshot
    # base timestamp (an upper bound: over-accepts BIP113 locktimes, can
    # reject a valid block as time-too-old) or by 0 (time-too-old disabled).
    db = MagicMock()
    db.get_median_time_past.return_value = None
    v = BlockValidator(db, network="mainnet", snapshot_manager=None)
    prev = _child_block(b"\x03" * 32, 1768401238)
    prev.bits = 0x1701EBF2
    v._lookup_header_block = lambda h: prev
    with pytest.raises(MissingAncestorHeaderError):
        v.validate_block(_child_block(b"\x04" * 32, 1768401889), known_height=BLOCK_H)


# ---------------------------------------------------------------- retarget


def _retarget_validator(first_ts):
    db = MagicMock()
    db.get_block_by_height.return_value = None  # no bodies below the base
    db.get_block_timestamp_by_height.side_effect = (
        lambda h: first_ts if h == 929376 else None
    )
    return BlockValidator(db, network="mainnet", snapshot_manager=None)


def _prev_931391() -> Block:
    b = _child_block(b"\x05" * 32, 1767858836)
    b.bits = 0x1701E605
    return b


def test_retarget_resolves_from_header_metadata_core_value():
    v = _retarget_validator(1766634486)
    bits, status = v._get_expected_bits(931392, _prev_931391(), _child_block(b"\x06" * 32, 1767859543))
    assert status == "ok"
    assert bits == 0x1701EBF2


def test_retarget_missing_period_first_fails_closed():
    # NEGATIVE CONTROL: pre-fix any nBits within 4x of prev was ACCEPTED here
    # ("accepted on the narrow fallback" — logged in every R4 slice).
    v = _retarget_validator(None)
    wrong = _child_block(b"\x06" * 32, 1767859543)
    wrong.bits = 0x1701E605  # within the 4x clamp, NOT Core's value
    with pytest.raises(MissingAncestorHeaderError):
        v._validate_header(wrong, _prev_931391(), block_mtp=1767855996,
                           height=931392, skip_pow=True)


def test_retarget_outside_clamp_still_rejected_without_ancestor():
    v = _retarget_validator(None)
    bad = _child_block(b"\x06" * 32, 1767859543)
    bad.bits = 0x1d00ffff  # difficulty 1 — outside any 4x clamp
    assert v._validate_header(bad, _prev_931391(), block_mtp=1767855996,
                              height=931392, skip_pow=True) is False


def test_retarget_with_metadata_rejects_wrong_bits():
    v = _retarget_validator(1766634486)
    wrong = _child_block(b"\x06" * 32, 1767859543)
    wrong.bits = 0x1701E605
    assert v._validate_header(wrong, _prev_931391(), block_mtp=1767855996,
                              height=931392, skip_pow=True) is False


# -------------------------------------------------------------- drain gate


def _bare_sync(complete: bool, done: bool):
    from ouroboros.block_sync import BlockSync

    bs = BlockSync.__new__(BlockSync)
    bs._prebase_headers_complete = complete
    bs._backfill_done = done
    bs._header_backfill = None
    bs._ibd_block_buffer = {b"\x07" * 32: (None, b"")}
    bs._validated_headers = [(b"\x07" * 32, None)]
    return bs


def test_drain_holds_until_prebase_headers_complete():
    bs = _bare_sync(complete=False, done=True)
    n = asyncio.run(bs._drain_block_buffer_locked())
    assert n == 0
    assert b"\x07" * 32 in bs._ibd_block_buffer  # untouched, not dropped


def test_request_next_blocks_held_until_prebase_headers_complete():
    bs = _bare_sync(complete=False, done=True)
    bs.db = MagicMock()
    bs.db.get_best_block.side_effect = AssertionError("must not get here")
    asyncio.run(bs._request_next_blocks())


def test_contiguous_index_releases_the_gate():
    bs = _bare_sync(complete=False, done=False)
    db = MagicMock()
    db.get_best_block.return_value = (b"\x08" * 32, 5)
    db.get_block_hash_by_height.side_effect = lambda h: bytes([h + 1]) * 32
    bs.db = db
    assert asyncio.run(bs._prebase_headers_ready()) is True
    assert bs._prebase_headers_complete is True


def test_index_gap_keeps_the_gate_closed_and_arms_backfill():
    bs = _bare_sync(complete=False, done=False)
    db = MagicMock()
    db.get_best_block.return_value = (b"\x08" * 32, 950)
    # snapshot shape: genesis present, 1..899 missing, 900..950 present
    db.get_block_hash_by_height.side_effect = (
        lambda h: (h.to_bytes(4, "little") * 8) if (h == 0 or h >= 900) else None
    )
    bs.db = db
    bs.peer_manager = MagicMock()
    bs.peer_manager.network = "mainnet"
    assert asyncio.run(bs._prebase_headers_ready()) is False
    assert bs._prebase_headers_complete is False
